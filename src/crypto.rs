use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};

// ── SPAKE2 ────────────────────────────────────────────────────────────────────

const ID_SENDER: &[u8] = b"wormhole-nym-sender";
const ID_RECEIVER: &[u8] = b"wormhole-nym-receiver";

/// Start SPAKE2 as the sender (side A). Returns the opaque state and the
/// message to send to the other side.
pub fn spake2_start_sender(password: &[u8]) -> (Spake2<Ed25519Group>, Vec<u8>) {
    Spake2::<Ed25519Group>::start_a(
        &Password::new(password),
        &Identity::new(ID_SENDER),
        &Identity::new(ID_RECEIVER),
    )
}

/// Start SPAKE2 as the receiver (side B).
pub fn spake2_start_receiver(password: &[u8]) -> (Spake2<Ed25519Group>, Vec<u8>) {
    Spake2::<Ed25519Group>::start_b(
        &Password::new(password),
        &Identity::new(ID_SENDER),
        &Identity::new(ID_RECEIVER),
    )
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derive two direction-specific 32-byte keys from the SPAKE2 shared secret.
///
/// * `send_key` — used by the sender to encrypt, by the receiver to decrypt.
/// * `recv_key` — used by the receiver to encrypt replies, by the sender to decrypt.
pub fn derive_keys(shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    let send_key = {
        let mut h = Sha256::new();
        h.update(shared_secret);
        h.update(b"wormhole-nym-send");
        h.finalize().into()
    };
    let recv_key = {
        let mut h = Sha256::new();
        h.update(shared_secret);
        h.update(b"wormhole-nym-recv");
        h.finalize().into()
    };
    (send_key, recv_key)
}

// ── Encryption / Decryption ───────────────────────────────────────────────────

fn make_nonce(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[..8].copy_from_slice(&counter.to_le_bytes());
    *Nonce::from_slice(&bytes)
}

/// Encrypt `plaintext` with the given key and counter-based nonce.
pub fn encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(&make_nonce(counter), plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption error: {e:?}"))
}

/// Decrypt `ciphertext` with the given key and counter-based nonce.
pub fn decrypt(key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(&make_nonce(counter), ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption error (wrong key or corrupted message): {e:?}"))
}

// ── Payload helpers ───────────────────────────────────────────────────────────

use crate::protocol::{decode, encode, Payload};

/// Serialise and encrypt a `Payload`.
pub fn seal(key: &[u8; 32], counter: u64, payload: &Payload) -> Result<Vec<u8>> {
    let plaintext = encode(payload).context("serialising payload")?;
    encrypt(key, counter, &plaintext)
}

/// Decrypt and deserialise a `Payload`.
pub fn open(key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> Result<Payload> {
    let plaintext = decrypt(key, counter, ciphertext)?;
    decode::<Payload>(&plaintext).context("deserialising payload")
}

// ── File hashing ──────────────────────────────────────────────────────────────

/// SHA-256 hash of an entire file.
pub fn hash_file(path: &std::path::Path) -> Result<[u8; 32]> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}
