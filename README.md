# wormhole-nym

**P2P file transfer over the [Nym mixnet](https://nymtech.net/) — no relay server, no rendezvous server.**

Inspired by [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole), but instead of using a central server for peer discovery and a transit relay for data, every byte travels through the Nym mixnet. The sender's Nym address *is* the rendezvous point. No infrastructure to trust or operate.

```
$ wormhole-nym send photo.jpg
Hashing photo.jpg…
Connecting to the Nym mixnet…

Wormhole code: fork-road-calm:8yGFbT5...@gateway

On the receiving machine run:
  wormhole-nym receive 'fork-road-calm:8yGFbT5...@gateway'

Waiting for the receiver to connect…
Receiver accepted the transfer.
Sending   [00:00:08] [==============] 2.31 MiB/2.31 MiB (1.24 MiB/s 0s)
Waiting for delivery confirmation (gateway queue is draining)…
✓ photo.jpg delivered and verified.
```

```
$ wormhole-nym receive 'fork-road-calm:8yGFbT5...@gateway'
Connecting to the Nym mixnet…
Sent handshake, waiting for sender…

Incoming file: photo.jpg (2423194 bytes / 2.31 MiB)
Accept? [y/N] y
Receiving [00:00:41] [==============] 2.31 MiB/2.31 MiB (57.6 KiB/s 0s)
✓ Saved to ./photo.jpg (SHA-256 verified)
```

---

## How it works

### The wormhole code

```
fork-road-calm:8yGFbT5ksqBMB...AGCFnPG@AXbTHwjZ...
└─────┬──────┘ └──────────────────────────────────┘
  SPAKE2 password       sender's Nym address
```

- The **Nym address** tells the receiver *where* to connect. It is a self-describing cryptographic identifier (ed25519 identity key + encryption key + gateway address), so no lookup server is needed.
- The **password** (3 random words) is used for SPAKE2 key exchange. It proves the receiver is the intended party and authenticates both sides against an impostor who might also know the sender's Nym address.

### Protocol

```
Receiver ──Hello{receiver_address, spake2_msg_B}──────────→ Sender
Receiver ←──PakeReply{spake2_msg_A}───────────────────────── Sender
Receiver ──Ready──────────────────────────────────────────→ Sender   (sync barrier)
Receiver ←──Encrypted(Offer{filename, size, sha256})──────── Sender
Receiver ──Encrypted(Accept)──────────────────────────────→ Sender
Receiver ←──Encrypted(Chunk{seq, data}) × N──────────────── Sender
Receiver ←──Encrypted(Done{total_chunks})─────────────────── Sender
Receiver ──Encrypted(Ack{sha256})─────────────────────────→ Sender
```

Either side may send `Encrypted(Error{message})` at any point to abort the transfer.

**Key exchange:** SPAKE2 (Ed25519Group) — password-authenticated, resists offline brute-force.

**Encryption:** ChaCha20-Poly1305 with direction-specific keys derived from the SPAKE2 shared secret via SHA-256 domain separation (`"wormhole-nym-send"` / `"wormhole-nym-recv"`). The counter embedded in each `Encrypted` message is the exact nonce used at encryption time.

**Integrity:** SHA-256 of the full file, verified by the receiver before sending `Ack`. The file is written to `<name>.part` during transfer and renamed to the final name only after the hash is verified.

**Mixnet reordering:** The Nym mixnet intentionally delays and shuffles packets. All incoming `Encrypted` messages are decrypted immediately using the counter from the message (correct nonce regardless of order) and held in a `BTreeMap` keyed by counter, then drained in order. This gives in-order delivery without TCP.

**Ready barrier:** After SPAKE2, the receiver sends `Ready` before the sender sends the `Offer`. Without this, the encrypted `Offer` can arrive before `PakeReply` due to mixnet reordering, making decryption impossible.

**Selective retransmission (ARQ):** If no packet arrives within 30 s the receiver sends a `Retransmit{counter}` request back to the sender. The sender re-reads the chunk from the file and resends it, plus a proactive window of 32 following chunks (they are likely missing from the same drop event). The receiver uses a 3 s follow-up timeout while recovering so consecutive losses are resolved in one round trip per 32-chunk window rather than one round trip per chunk.

**Sender disconnect timing:** The sender does not call `disconnect()` until it receives the `Ack`. This is critical: for large files the sender's local Nym client can have thousands of packets queued for the gateway when the send loop finishes. Disconnecting early drops those packets and leaves the receiver incomplete. The `Ack` proves every byte was received.

**Graceful cancellation:** Ctrl+C on the receiver sends `Encrypted(Error)` to the sender, which stops the send loop within 512 KiB. The `.part` file is kept on disk. If the sender is killed without sending an `Error`, the receiver detects 60 s of no progress and exits on its own. The sender has a 30-minute hard timeout on the Ack wait for the same reason.

---

## Building

```sh
git clone <this repo>
cd wormhole-nym
cargo build --release
# binary: target/release/wormhole-nym
```

### Requirements

- Rust 1.75+
- Network access to the Nym mainnet (no local Nym node required)

---

## Usage

### Send a file

```sh
wormhole-nym send <file>
```

Prints a wormhole code. Share it with the recipient over any channel (chat, email, etc.). The code is only useful once — it encodes a one-time ephemeral Nym identity.

### Receive a file

```sh
wormhole-nym receive '<code>'          # saves to current directory
wormhole-nym receive '<code>' -o ~/Downloads
```

The file is saved as `<name>.part` until the SHA-256 hash is verified, then renamed to the final name.

### Concurrency

Each invocation is fully independent — separate Nym client, separate ephemeral identity, separate gateway connection. Running multiple transfers concurrently works without interference.

### Debug logging

Nym internal logs are suppressed by default. To see them:

```sh
RUST_LOG=warn wormhole-nym send file.txt   # show Nym warnings
RUST_LOG=debug wormhole-nym send file.txt  # show everything
```

---

## Architecture

```
src/
  main.rs       CLI (clap)
  words.rs      361-word list, generates 3-word SPAKE2 passwords
  protocol.rs   Msg / Payload enums, bincode serialisation
  crypto.rs     SPAKE2 wrappers, ChaCha20-Poly1305 helpers, SHA-256 file hash
  send.rs       Sender state machine
  receive.rs    Receiver state machine (with BTreeMap reorder buffer + ARQ)
vendor/         Local patches for broken nym-sdk 1.20.4 crates (see below)
```

Chunk size is 32 KiB. Each chunk is individually encrypted and carries a sequence number. The receiver buffers out-of-order chunks and writes them to disk in order.

---

## Known issues and improvements needed

### 1. Nym SDK 1.20.4 has broken published crates

`nym-sdk 1.20.4` is the only version published on crates.io as of March 2026. Three of its internal crates (`nym-noise`, `nym-node-requests`, `nym-api-requests`) reference a type `VersionedNoiseKey` that was renamed to `VersionedNoiseKeyV1` in `nym-noise-keys 1.20.5` without a corresponding update.

**Current workaround:** The `vendor/` directory contains copies of those three crates with a one-line fix (`VersionedNoiseKey` → `VersionedNoiseKeyV1 as VersionedNoiseKey`), referenced via `[patch.crates-io]` in `Cargo.toml`.

**What to do when fixed:** Remove the `vendor/` directory and the `[patch.crates-io]` section from `Cargo.toml` once `nym-sdk 1.20.5`+ is published.

**How to re-apply the vendor patch** (e.g. after `cargo clean`):
```sh
for crate in nym-noise-1.20.4 nym-node-requests-1.20.4 nym-api-requests-1.20.4; do
  name="${crate%-1.20.4}"
  cp -r ~/.cargo/registry/src/index.crates.io-*/$crate vendor/$name
  find vendor/$name -name "*.rs" -exec sed -i \
    's/use nym_noise_keys::\(.*\)VersionedNoiseKey;/use nym_noise_keys::\1VersionedNoiseKeyV1 as VersionedNoiseKey;/g' {} \;
done
```

### 2. Gateway queue backlog and transfer speed

The Nym client queues outgoing packets in a local buffer and drains them into the gateway asynchronously. For large files this queue reaches thousands of packets and the sender must remain connected long after the send loop finishes — visibly, the sender shows "gateway queue is draining" while the receiver is still receiving.

In practice, the gateway can drop a tail of packets when the queue grows very large. The ARQ retransmission mechanism handles this, but it adds latency. Possible improvements:
- Expose the queue depth via the Nym SDK and show it as a second progress indicator.
- Implement application-level flow control: pause sending when the backlog exceeds a threshold, so the queue never grows unboundedly. This would reduce end-to-end latency for large files and reduce packet loss.
- Use the Nym SDK's stream mode (TCP-like abstraction) if it becomes stable — it may handle backpressure internally.

### 3. No streaming / directory support

Currently only single files are supported. Improvements:
- Directory transfer: tar the directory on the fly (streaming, no temp file) and untar on the receiver side.
- Pipe mode: `cat file | wormhole-nym send -` / `wormhole-nym receive code | tar xf -`.

### 4. Ephemeral-only Nym identity

Both sender and receiver use `MixnetClientBuilder::new_ephemeral()`, generating a fresh keypair each run and paying the gateway registration cost (~10–30 s startup) every time.

A persistent identity mode (`new_with_default_storage`) would allow:
- Reusing a registered gateway slot across transfers (faster startup).
- A "receive server" mode: run once, display your permanent Nym address, accept transfers from anyone who knows it.

### 5. No progress on the sender side during queue drain

After the send loop finishes, the sender shows a static message while waiting for the Ack. The Nym SDK logs the backlog count but does not expose it via a public API. If the SDK exposes this metric in a future version, it could be displayed as a second progress bar ("queue draining: 4200 → 0 packets").

### 6. Single-recipient only

The wormhole code encodes a single sender Nym address. A future improvement could allow broadcasting to multiple recipients by sending each a separate encrypted copy, or by using Nym's anonymous reply (SURB) mechanism so the sender doesn't need to know recipient addresses in advance.
