use std::{collections::BTreeMap, io::Write, path::PathBuf, time::Instant};

use anyhow::{bail, Context, Result};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use nym_sdk::mixnet::{MixnetClientBuilder, MixnetMessageSender, Recipient};
use sha2::{Digest, Sha256};

use crate::{
    crypto::{derive_keys, open, seal, spake2_start_receiver},
    protocol::{decode, encode, Msg, Payload},
};

/// Parse a wormhole code into (password, sender_nym_address_string).
/// Code format: "word-word-word:NymAddress"
fn parse_code(code: &str) -> Result<(&str, &str)> {
    let colon = code
        .find(':')
        .context("Invalid wormhole code: expected format 'word-word-word:NymAddress'")?;
    Ok((&code[..colon], &code[colon + 1..]))
}

/// Receive the next in-order `Payload` from the sender.
///
/// Because the Nym mixnet reorders packets, we decrypt each incoming
/// `Msg::Encrypted` using the counter embedded in the message (which is the
/// ChaCha20-Poly1305 nonce used at encryption time), insert it into `buf`
/// keyed by that counter, and then drain the lowest-counter entry.  This gives
/// us the same in-order processing that TCP would provide.
/// How long to wait for a message during normal flow before declaring a stall.
const RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Short follow-up timeout used while recovering from packet loss.
/// After each retransmit we stay in fast mode so consecutive missing counters
/// are recovered without waiting the full RECV_TIMEOUT between each one.
const RETRANSMIT_FOLLOWUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Receive the next in-order `Payload`.
///
/// `timeout` controls how long to wait for a message before returning
/// `Ok(None)` (stall signal). The caller should then request retransmission
/// and call again with `RETRANSMIT_FOLLOWUP_TIMEOUT` for faster recovery.
async fn next_payload(
    client: &mut nym_sdk::mixnet::MixnetClient,
    key: &[u8; 32],
    buf: &mut BTreeMap<u64, Payload>,
    next_ctr: &mut u64,
    timeout: std::time::Duration,
) -> Result<Option<Payload>> {
    loop {
        // Return the next buffered in-order payload if available.
        if let Some(payload) = buf.remove(next_ctr) {
            *next_ctr += 1;
            return Ok(Some(payload));
        }
        // Otherwise receive another message from the mixnet and buffer it.
        let raw = match tokio::time::timeout(timeout, client.next()).await {
            Err(_) => return Ok(None), // stalled — caller will request retransmit
            Ok(msg) => msg.context("Connection closed during transfer")?,
        };
        match decode::<Msg>(&raw.message)? {
            Msg::Encrypted {
                counter,
                ciphertext,
            } => {
                // Decrypt with the nonce embedded in the message — correct even
                // when messages arrive out of order.
                let payload = open(key, counter, &ciphertext)
                    .with_context(|| format!("decryption failed for counter {counter}"))?;
                buf.insert(counter, payload);
            }
            other => bail!("Expected Encrypted message, got {other:?}"),
        }
    }
}

pub async fn receive_file(code: String, output_dir: PathBuf, gateway: Option<String>) -> Result<()> {
    // ── Parse wormhole code ───────────────────────────────────────────────────
    let (password, sender_addr_str) = parse_code(&code)?;
    let sender_addr: Recipient = Recipient::try_from_base58_string(sender_addr_str)
        .map_err(|e| anyhow::anyhow!("Invalid sender Nym address in code: {e}"))?;

    // ── Connect to Nym mixnet ─────────────────────────────────────────────────
    eprintln!("Connecting to the Nym mixnet…");
    let mut builder = MixnetClientBuilder::new_ephemeral();
    if let Some(gw) = gateway {
        builder = builder.request_gateway(gw);
    }
    let mut client = builder
        .build()
        .context("Failed to build Nym client")?
        .connect_to_mixnet()
        .await
        .context("Failed to connect to Nym mixnet")?;

    let our_address = client.nym_address().to_string();

    // ── SPAKE2 — start as receiver (side B) ───────────────────────────────────
    let (spake_state, our_pake_msg) = spake2_start_receiver(password.as_bytes());

    // ── Send Hello (receiver → sender) ───────────────────────────────────────
    client
        .send_plain_message(
            sender_addr,
            encode(&Msg::Hello {
                receiver_address: our_address,
                pake_msg: our_pake_msg,
            })?,
        )
        .await
        .context("sending Hello")?;
    eprintln!("Sent handshake, waiting for sender…");

    // ── Wait for PakeReply (sender → receiver) ────────────────────────────────
    let pake_raw = client
        .next()
        .await
        .context("Connection closed before PakeReply")?;
    let sender_pake_msg = match decode::<Msg>(&pake_raw.message)? {
        Msg::PakeReply { pake_msg } => pake_msg,
        other => bail!("Expected PakeReply, got {other:?}"),
    };

    // ── Finish SPAKE2 ─────────────────────────────────────────────────────────
    let shared_secret = spake_state
        .finish(&sender_pake_msg)
        .map_err(|e| anyhow::anyhow!("SPAKE2 key exchange failed: {e:?}"))?;
    let (send_key, recv_key) = derive_keys(&shared_secret);
    // send_key: sender encrypts  → we decrypt
    // recv_key: we encrypt       → sender decrypts
    let mut recv_ctr: u64 = 0; // our outgoing encryption counter

    // ── Send Ready ────────────────────────────────────────────────────────────
    // Tells the sender we have derived the shared key. The sender waits for
    // this before sending the Offer, preventing reordering (Offer arriving
    // before PakeReply).
    client
        .send_plain_message(sender_addr, encode(&Msg::Ready)?)
        .await
        .context("sending Ready")?;

    // ── Shared receive buffer ─────────────────────────────────────────────────
    // Decrypted payloads keyed by their counter value. `next_payload()` drains
    // them in order, buffering anything that arrives early.
    let mut buf: BTreeMap<u64, Payload> = BTreeMap::new();
    let mut next_ctr: u64 = 0;

    // ── Wait for Offer ────────────────────────────────────────────────────────
    let (filename, filesize, expected_sha256) = match next_payload(
        &mut client,
        &send_key,
        &mut buf,
        &mut next_ctr,
        RECV_TIMEOUT,
    )
    .await?
    {
        Some(Payload::Offer {
            filename,
            filesize,
            sha256,
        }) => (filename, filesize, sha256),
        other => bail!("Expected Offer, got {other:?}"),
    };

    // ── Prompt user ───────────────────────────────────────────────────────────
    println!();
    println!(
        "Incoming file: {} ({} bytes / {:.2} MiB)",
        filename,
        filesize,
        filesize as f64 / (1024.0 * 1024.0)
    );
    print!("Accept? [y/N] ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if !input.trim().eq_ignore_ascii_case("y") {
        let reject_ct = seal(
            &recv_key,
            recv_ctr,
            &Payload::Reject {
                reason: "User declined".into(),
            },
        )?;
        client
            .send_plain_message(
                sender_addr,
                encode(&Msg::Encrypted {
                    counter: recv_ctr,
                    ciphertext: reject_ct,
                })?,
            )
            .await?;
        client.disconnect().await;
        return Ok(());
    }

    // ── Send Accept ───────────────────────────────────────────────────────────
    let accept_ct = seal(&recv_key, recv_ctr, &Payload::Accept)?;
    client
        .send_plain_message(
            sender_addr,
            encode(&Msg::Encrypted {
                counter: recv_ctr,
                ciphertext: accept_ct,
            })?,
        )
        .await?;
    recv_ctr += 1;

    // ── Receive chunks ────────────────────────────────────────────────────────
    let output_path = output_dir.join(&filename);
    let part_path = output_dir.join(format!("{filename}.part"));
    let mut file = std::io::BufWriter::new(
        std::fs::File::create(&part_path)
            .with_context(|| format!("Cannot create {}", part_path.display()))?,
    );

    let mut hasher = Sha256::new();
    let bar = ProgressBar::new(filesize);
    bar.set_style(
        ProgressStyle::with_template(
            "Receiving [{elapsed_precise}] [{wide_bar:.green/black}] {bytes}/{total_bytes} ({binary_bytes_per_sec} {eta})",
        )
        .unwrap()
        .progress_chars("=>-"),
    );

    // Arm a Ctrl+C listener for the transfer phase. If the user cancels we
    // notify the sender, delete the partial file, and exit cleanly.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    // Process payloads in counter order. Because `next_payload` buffers
    // out-of-order messages and drains them lowest-counter-first, chunks
    // are guaranteed to be written to disk in the correct sequence.
    //
    // `recv_timeout` starts at RECV_TIMEOUT (30s) for normal flow. After any
    // retransmit request it drops to RETRANSMIT_FOLLOWUP_TIMEOUT (5s) so
    // consecutive missing counters are recovered without a 30s wait each.
    // It resets to the slow timeout once the reorder buffer is non-empty,
    // indicating packets are flowing normally again.
    let mut recv_timeout = RECV_TIMEOUT;
    let mut last_progress = Instant::now();
    let transfer_result: anyhow::Result<()> = loop {
        tokio::select! {
            biased;

            // Check for Ctrl+C first (biased: checked every iteration before blocking).
            _ = &mut ctrl_c => {
                bar.abandon_with_message("cancelled");
                break Err(anyhow::anyhow!("cancelled by user"));
            }

            result = next_payload(&mut client, &send_key, &mut buf, &mut next_ctr, recv_timeout) => {
                match result? {
                    None => {
                        // Timed out waiting for counter `next_ctr`.
                        // If no chunk has arrived for 120s, assume the sender
                        // is dead and stop waiting.
                        if last_progress.elapsed() > std::time::Duration::from_secs(120) {
                            bar.abandon_with_message("sender disconnected");
                            break Err(anyhow::anyhow!("no progress for 120s — sender disconnected"));
                        }
                        // Batch-request all consecutive missing counters we can
                        // identify from the reorder buffer right now.
                        let missing = next_ctr;
                        let batch_end = buf
                            .keys()
                            .next()
                            .copied()
                            .unwrap_or(missing + 1)
                            .min(missing + 32); // cap to avoid flooding
                        recv_timeout = RETRANSMIT_FOLLOWUP_TIMEOUT;
                        for ctr in missing..batch_end {
                            let ct = seal(&recv_key, recv_ctr, &Payload::Retransmit { counter: ctr })?;
                            client
                                .send_plain_message(
                                    sender_addr,
                                    encode(&Msg::Encrypted { counter: recv_ctr, ciphertext: ct })?,
                                )
                                .await
                                .context("sending Retransmit")?;
                            recv_ctr += 1;
                        }
                    }
                    Some(Payload::Chunk { seq: _, data }) => {
                        last_progress = Instant::now();
                        // Back to slow timeout once buffer has entries — packets are
                        // flowing, no need to aggressively poll.
                        if !buf.is_empty() {
                            recv_timeout = RECV_TIMEOUT;
                        }
                        bar.inc(data.len() as u64);
                        hasher.update(&data);
                        file.write_all(&data)?;
                    }
                    Some(Payload::Done { .. }) => {
                        break Ok(());
                    }
                    Some(Payload::Error { message }) => {
                        bail!("Sender reported an error: {message}");
                    }
                    Some(other) => bail!("Unexpected payload during transfer: {other:?}"),
                }
            }
        }
    };

    if let Err(e) = transfer_result {
        // Tell the sender we aborted so it can stop sending immediately.
        if let Ok(ct) = seal(
            &recv_key,
            recv_ctr,
            &Payload::Error {
                message: e.to_string(),
            },
        ) {
            if let Ok(encoded) = encode(&Msg::Encrypted {
                counter: recv_ctr,
                ciphertext: ct,
            }) {
                let _ = client.send_plain_message(sender_addr, encoded).await;
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
        drop(file);
        eprintln!("Partial file kept at {}", part_path.display());
        client.disconnect().await;
        return Err(e);
    }

    bar.finish_with_message("done");
    file.flush()?;
    drop(file);

    // ── Verify integrity ──────────────────────────────────────────────────────
    let actual_sha256: [u8; 32] = hasher.finalize().into();
    let verified = actual_sha256 == expected_sha256;

    // ── Send Ack ──────────────────────────────────────────────────────────────
    let ack_ct = seal(
        &recv_key,
        recv_ctr,
        &Payload::Ack {
            sha256: actual_sha256,
        },
    )?;
    client
        .send_plain_message(
            sender_addr,
            encode(&Msg::Encrypted {
                counter: recv_ctr,
                ciphertext: ack_ct,
            })?,
        )
        .await?;

    if verified {
        std::fs::rename(&part_path, &output_path).with_context(|| {
            format!(
                "Cannot rename {} to {}",
                part_path.display(),
                output_path.display()
            )
        })?;
        println!("✓ Saved to {} (SHA-256 verified)", output_path.display());
    } else {
        eprintln!(
            "✗ SHA-256 mismatch — file kept at {} (may be corrupted).",
            part_path.display()
        );
    }

    // Give the gateway time to forward the Ack before we tear down.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    client.disconnect().await;
    Ok(())
}
