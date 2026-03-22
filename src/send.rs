use std::{
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use futures::{FutureExt, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use nym_sdk::mixnet::{MixnetClientBuilder, MixnetMessageSender, Recipient};

use crate::{
    crypto::{derive_keys, hash_file, open, seal, spake2_start_sender},
    protocol::{decode, encode, Msg, Payload},
    words::generate_password,
};

/// Maximum bytes per Nym message. The SDK handles fragmentation, but keeping
/// chunks moderate avoids excessive latency from large Sphinx packet trains.
const CHUNK_SIZE: usize = 32 * 1024; // 32 KiB

pub async fn send_file(path: PathBuf) -> Result<()> {
    // ── File metadata ─────────────────────────────────────────────────────────
    let metadata = std::fs::metadata(&path)
        .with_context(|| format!("Cannot read file: {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a file", path.display());
    }
    let filesize = metadata.len();
    let filename = path
        .file_name()
        .context("file has no name")?
        .to_string_lossy()
        .into_owned();

    eprintln!("Hashing {filename}…");
    let sha256 = hash_file(&path)?;

    // ── Connect to Nym mixnet ─────────────────────────────────────────────────
    eprintln!("Connecting to the Nym mixnet…");
    let mut client = MixnetClientBuilder::new_ephemeral()
        .build()
        .context("Failed to build Nym client")?
        .connect_to_mixnet()
        .await
        .context("Failed to connect to Nym mixnet")?;

    let our_address = *client.nym_address();

    // ── Generate wormhole code ────────────────────────────────────────────────
    let password = generate_password(3);
    // Code format:  "word-word-word:NymAddress"
    // The receiver parses this by splitting on the first ':'.
    let code = format!("{password}:{our_address}");

    println!();
    println!("Wormhole code: {code}");
    println!();
    println!("On the receiving machine run:");
    println!("  wormhole-nym receive '{code}'");
    println!();
    println!("Waiting for the receiver to connect…");

    // ── Wait for Hello (receiver → sender) ───────────────────────────────────
    let hello_raw = client
        .next()
        .await
        .context("Connection closed before Hello")?;
    let hello_msg: Msg = decode(&hello_raw.message).context("decoding Hello")?;
    let (receiver_address, peer_pake_msg) = match hello_msg {
        Msg::Hello {
            receiver_address,
            pake_msg,
        } => (receiver_address, pake_msg),
        other => bail!("Expected Hello, got {other:?}"),
    };
    let receiver_addr: Recipient = Recipient::try_from_base58_string(&receiver_address)
        .map_err(|e| anyhow::anyhow!("Invalid receiver Nym address: {e}"))?;

    // ── SPAKE2 key exchange ───────────────────────────────────────────────────
    let (spake_state, our_pake_msg) = spake2_start_sender(password.as_bytes());

    let pake_reply = encode(&Msg::PakeReply {
        pake_msg: our_pake_msg,
    })?;
    client
        .send_plain_message(receiver_addr, pake_reply)
        .await
        .context("sending PakeReply")?;

    let shared_secret = spake_state
        .finish(&peer_pake_msg)
        .map_err(|e| anyhow::anyhow!("SPAKE2 key exchange failed: {e:?}"))?;
    let (send_key, recv_key) = derive_keys(&shared_secret);
    let mut send_ctr: u64 = 0; // our encryption counter

    // ── Wait for Ready ────────────────────────────────────────────────────────
    // The receiver sends Ready after it has completed SPAKE2 and derived its
    // keys. We must not send the encrypted Offer until we receive Ready,
    // because the Nym mixnet can reorder messages: without this barrier the
    // Offer can arrive before PakeReply and the receiver can't decrypt it.
    let ready_raw = client
        .next()
        .await
        .context("Connection closed waiting for Ready")?;
    match decode::<Msg>(&ready_raw.message)? {
        Msg::Ready => {}
        other => bail!("Expected Ready, got {other:?}"),
    }

    // ── Send file offer ───────────────────────────────────────────────────────
    let offer_ct = seal(
        &send_key,
        send_ctr,
        &Payload::Offer {
            filename: filename.clone(),
            filesize,
            sha256,
        },
    )?;
    client
        .send_plain_message(receiver_addr, encode(&Msg::Encrypted { counter: send_ctr, ciphertext: offer_ct })?)
        .await?;
    send_ctr += 1;

    // ── Wait for Accept / Reject ──────────────────────────────────────────────
    let resp_raw = client
        .next()
        .await
        .context("Connection closed waiting for Accept")?;
    let resp_msg: Msg = decode(&resp_raw.message)?;
    match resp_msg {
        Msg::Encrypted { counter, ciphertext } => {
            // Use the counter from the message as the decryption nonce — correct
            // even if messages arrive out of order.
            match open(&recv_key, counter, &ciphertext)? {
                Payload::Accept => {
                    eprintln!("Receiver accepted the transfer.");
                }
                Payload::Reject { reason } => {
                    eprintln!("Receiver rejected: {reason}");
                    client.disconnect().await;
                    return Ok(());
                }
                other => bail!("Expected Accept/Reject, got {other:?}"),
            }
        }
        other => bail!("Expected Encrypted, got {other:?}"),
    }

    // ── Send file chunks ──────────────────────────────────────────────────────
    let bar = ProgressBar::new(filesize);
    bar.set_style(
        ProgressStyle::with_template(
            "Sending   [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({binary_bytes_per_sec} {eta})",
        )
        .unwrap()
        .progress_chars("=>-"),
    );

    let file = std::fs::File::open(&path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut seq: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk_ct = seal(
            &send_key,
            send_ctr,
            &Payload::Chunk {
                seq,
                data: buf[..n].to_vec(),
            },
        )?;
        client
            .send_plain_message(
                receiver_addr,
                encode(&Msg::Encrypted { counter: send_ctr, ciphertext: chunk_ct })?,
            )
            .await
            .with_context(|| format!("sending chunk {seq}"))?;
        send_ctr += 1;
        seq += 1;
        bar.inc(n as u64);

        // Every 16 chunks, non-blocking check for an abort from the receiver.
        if seq.is_multiple_of(16) {
            if let Some(Some(raw)) = client.next().now_or_never() {
                if let Ok(Msg::Encrypted { counter, ciphertext }) = decode::<Msg>(&raw.message) {
                    if let Ok(Payload::Error { message }) = open(&recv_key, counter, &ciphertext) {
                        bar.abandon_with_message("receiver aborted");
                        client.disconnect().await;
                        bail!("Receiver aborted: {message}");
                    }
                }
            }
        }
    }
    bar.finish_with_message("done");
    let total_chunks = seq;

    // ── Send Done ─────────────────────────────────────────────────────────────
    let done_ct = seal(&send_key, send_ctr, &Payload::Done { total_chunks })?;
    client
        .send_plain_message(
            receiver_addr,
            encode(&Msg::Encrypted { counter: send_ctr, ciphertext: done_ct })?,
        )
        .await?;

    // ── Wait for Ack (with retransmit support) ───────────────────────────────
    // IMPORTANT: do not disconnect before the Ack arrives.
    //
    // The Nym client keeps a local packet queue that drains asynchronously into
    // the gateway.  For large files this queue can hold thousands of packets
    // that have not yet been forwarded when we finish the send loop.  Calling
    // disconnect() while the queue is non-empty drops those packets and leaves
    // the receiver incomplete.  Waiting for the Ack guarantees the receiver has
    // reconstructed every chunk before we tear down the connection.
    //
    // While waiting, we also handle Retransmit requests: if the receiver detects
    // a missing counter (packet loss), it sends back a Retransmit message and we
    // re-read that chunk from the file and resend it.
    //
    // A 30-minute hard timeout handles kill-9 cases where the receiver dies
    // without sending an Error.
    eprintln!("Waiting for delivery confirmation (gateway queue is draining)…");
    'ack: loop {
        let raw = match tokio::time::timeout(
            std::time::Duration::from_secs(30 * 60),
            client.next(),
        )
        .await
        {
            Err(_) => {
                client.disconnect().await;
                bail!("Timed out waiting for Ack — receiver may have disconnected");
            }
            Ok(msg) => msg.context("Connection closed waiting for Ack")?,
        };

        match decode::<Msg>(&raw.message)? {
            Msg::Encrypted { counter, ciphertext } => {
                match open(&recv_key, counter, &ciphertext)? {
                    Payload::Ack { sha256: received_hash } => {
                        if received_hash == sha256 {
                            println!("✓ {filename} delivered and verified.");
                        } else {
                            eprintln!("✗ SHA-256 mismatch — file may be corrupted in transit.");
                        }
                        break 'ack;
                    }
                    Payload::Retransmit { counter: req_ctr } => {
                        // Re-send starting at req_ctr plus a proactive window of
                        // following counters: they likely belong to the same drop
                        // event, so sending them now saves one round trip each.
                        // counter 0       = Offer
                        // counter 1..=N   = Chunk (seq = ctr - 1)
                        // counter N+1     = Done
                        const RETRANSMIT_WINDOW: u64 = 32;
                        let window_end = (req_ctr + RETRANSMIT_WINDOW).min(total_chunks + 2);
                        let mut retrans_file = std::fs::File::open(&path)?;
                        for ctr in req_ctr..window_end {
                            let ct = if ctr == 0 {
                                seal(&send_key, 0, &Payload::Offer {
                                    filename: filename.clone(),
                                    filesize,
                                    sha256,
                                })?
                            } else if ctr <= total_chunks {
                                let chunk_seq = ctr - 1;
                                let file_offset = chunk_seq * CHUNK_SIZE as u64;
                                retrans_file.seek(SeekFrom::Start(file_offset))?;
                                let mut chunk_buf = vec![0u8; CHUNK_SIZE];
                                let n = retrans_file.read(&mut chunk_buf)?;
                                seal(&send_key, ctr, &Payload::Chunk {
                                    seq: chunk_seq,
                                    data: chunk_buf[..n].to_vec(),
                                })?
                            } else {
                                seal(&send_key, ctr, &Payload::Done { total_chunks })?
                            };
                            client
                                .send_plain_message(
                                    receiver_addr,
                                    encode(&Msg::Encrypted { counter: ctr, ciphertext: ct })?,
                                )
                                .await?;
                        }
                    }
                    Payload::Error { message } => {
                        client.disconnect().await;
                        bail!("Receiver aborted: {message}");
                    }
                    other => bail!("Expected Ack, got {other:?}"),
                }
            }
            other => bail!("Expected Encrypted, got {other:?}"),
        }
    }
    client.disconnect().await;
    Ok(())
}
