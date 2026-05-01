//! WebAssembly bindings for the wormhole-nym protocol layer.
//!
//! Exposes the crypto and SPAKE2 primitives so a web app can share
//! bit-perfect protocol logic with the CLI without reimplementing it in JS.
//! The Nym JS SDK handles transport on the web side.
//!
//! Build with:
//!   wasm-pack build wasm --target web

use wasm_bindgen::prelude::*;
use wormhole_nym_core::{
    crypto::{derive_keys, open, seal, spake2_start_receiver, spake2_start_sender},
    words::generate_password,
};

// ── Word-code generation ──────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn wasm_generate_password(num_words: usize) -> String {
    generate_password(num_words)
}

// ── SPAKE2 ────────────────────────────────────────────────────────────────────

/// Opaque SPAKE2 sender state.  Create with `spake2_sender_start`, consume
/// with `spake2_sender_finish`.
#[wasm_bindgen]
pub struct Spake2SenderState {
    inner: Option<spake2::Spake2<spake2::Ed25519Group>>,
}

#[wasm_bindgen]
impl Spake2SenderState {
    /// Start SPAKE2 as the sender.  Returns the message to send to the receiver.
    pub fn start(password: &[u8]) -> Result<StartResult, JsError> {
        let (state, msg) = spake2_start_sender(password);
        Ok(StartResult {
            state: Spake2SenderState { inner: Some(state) },
            pake_msg: msg,
        })
    }

    /// Finish SPAKE2 with the receiver's message.  Returns the raw shared secret.
    pub fn finish(&mut self, peer_msg: &[u8]) -> Result<Vec<u8>, JsError> {
        let state = self.inner.take().ok_or_else(|| JsError::new("already consumed"))?;
        state
            .finish(peer_msg)
            .map_err(|e| JsError::new(&format!("SPAKE2 failed: {e:?}")))
    }
}

#[wasm_bindgen]
pub struct StartResult {
    state: Spake2SenderState,
    pake_msg: Vec<u8>,
}

#[wasm_bindgen]
impl StartResult {
    pub fn take_state(self) -> Spake2SenderState {
        self.state
    }
    pub fn pake_msg(&self) -> Vec<u8> {
        self.pake_msg.clone()
    }
}

/// Opaque SPAKE2 receiver state.
#[wasm_bindgen]
pub struct Spake2ReceiverState {
    inner: Option<spake2::Spake2<spake2::Ed25519Group>>,
}

#[wasm_bindgen]
impl Spake2ReceiverState {
    pub fn start(password: &[u8]) -> Result<ReceiverStartResult, JsError> {
        let (state, msg) = spake2_start_receiver(password);
        Ok(ReceiverStartResult {
            state: Spake2ReceiverState { inner: Some(state) },
            pake_msg: msg,
        })
    }

    pub fn finish(&mut self, peer_msg: &[u8]) -> Result<Vec<u8>, JsError> {
        let state = self.inner.take().ok_or_else(|| JsError::new("already consumed"))?;
        state
            .finish(peer_msg)
            .map_err(|e| JsError::new(&format!("SPAKE2 failed: {e:?}")))
    }
}

#[wasm_bindgen]
pub struct ReceiverStartResult {
    state: Spake2ReceiverState,
    pake_msg: Vec<u8>,
}

#[wasm_bindgen]
impl ReceiverStartResult {
    pub fn take_state(self) -> Spake2ReceiverState {
        self.state
    }
    pub fn pake_msg(&self) -> Vec<u8> {
        self.pake_msg.clone()
    }
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derive send/recv keys from a SPAKE2 shared secret.
/// Returns a 64-byte buffer: first 32 bytes = send_key, next 32 = recv_key.
#[wasm_bindgen]
pub fn wasm_derive_keys(shared_secret: &[u8]) -> Vec<u8> {
    let (send_key, recv_key) = derive_keys(shared_secret);
    [send_key, recv_key].concat()
}

// ── Seal / open ───────────────────────────────────────────────────────────────

/// Serialize and encrypt a `Payload` (bincode + ChaCha20-Poly1305).
/// `payload_bytes` is a bincode-encoded `Payload`.
#[wasm_bindgen]
pub fn wasm_seal(key: &[u8], counter: u64, payload_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    use wormhole_nym_core::protocol::decode;
    use wormhole_nym_core::protocol::Payload;
    let key: &[u8; 32] = key.try_into().map_err(|_| JsError::new("key must be 32 bytes"))?;
    let payload: Payload = decode(payload_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    seal(key, counter, &payload).map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypt and deserialize, returning a bincode-encoded `Payload`.
#[wasm_bindgen]
pub fn wasm_open(key: &[u8], counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    use wormhole_nym_core::protocol::encode;
    let key: &[u8; 32] = key.try_into().map_err(|_| JsError::new("key must be 32 bytes"))?;
    let payload = open(key, counter, ciphertext).map_err(|e| JsError::new(&e.to_string()))?;
    encode(&payload).map_err(|e| JsError::new(&e.to_string()))
}

// ── Raw crypto primitives ─────────────────────────────────────────────────────

/// Raw ChaCha20-Poly1305 encryption (no Payload encoding).
/// Matches `crypto::encrypt` from wormhole-nym-core exactly.
#[wasm_bindgen]
pub fn wasm_encrypt(key: &[u8], counter: u64, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    use wormhole_nym_core::crypto::encrypt;
    let key: &[u8; 32] = key.try_into().map_err(|_| JsError::new("key must be 32 bytes"))?;
    encrypt(key, counter, plaintext).map_err(|e| JsError::new(&e.to_string()))
}

/// Raw ChaCha20-Poly1305 decryption (no Payload decoding).
/// Matches `crypto::decrypt` from wormhole-nym-core exactly.
#[wasm_bindgen]
pub fn wasm_decrypt(key: &[u8], counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    use wormhole_nym_core::crypto::decrypt;
    let key: &[u8; 32] = key.try_into().map_err(|_| JsError::new("key must be 32 bytes"))?;
    decrypt(key, counter, ciphertext).map_err(|e| JsError::new(&e.to_string()))
}

/// SHA-256 of arbitrary bytes — matches `sha2::Sha256` used throughout wormhole-nym-core.
#[wasm_bindgen]
pub fn wasm_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}
