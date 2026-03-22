use serde::{Deserialize, Serialize};

/// All messages exchanged over the Nym mixnet.
///
/// Phase 1 (unencrypted): Hello + PakeReply establish the shared SPAKE2 key.
/// Phase 2 (encrypted):   All subsequent messages are wrapped in Encrypted.
#[derive(Serialize, Deserialize, Debug)]
pub enum Msg {
    /// Sent by the receiver to the sender to initiate the transfer.
    /// Carries the receiver's Nym address (so the sender knows where to reply)
    /// and the receiver's SPAKE2 message.
    Hello {
        receiver_address: String,
        pake_msg: Vec<u8>,
    },

    /// Sender's SPAKE2 reply. After both sides process each other's pake_msg,
    /// both derive the same symmetric key.
    PakeReply { pake_msg: Vec<u8> },

    /// Sent by the receiver to the sender after completing SPAKE2, signalling
    /// that it has derived the shared key and is ready to receive the Offer.
    /// This synchronisation step prevents the Offer from arriving before
    /// PakeReply due to Nym mixnet message reordering.
    Ready,

    /// An encrypted payload. `counter` is the sender's monotonic nonce counter,
    /// used to construct the ChaCha20-Poly1305 nonce.
    Encrypted { counter: u64, ciphertext: Vec<u8> },
}

/// Payloads that travel inside `Msg::Encrypted`.
#[derive(Serialize, Deserialize, Debug)]
pub enum Payload {
    /// Sender describes the file it wants to transfer.
    Offer {
        filename: String,
        filesize: u64,
        /// SHA-256 of the whole file, for integrity verification.
        sha256: [u8; 32],
    },

    /// Receiver accepts the offer and is ready for chunks.
    Accept,

    /// Receiver declines.
    Reject { reason: String },

    /// One chunk of file data. `seq` is the zero-based chunk index.
    Chunk { seq: u64, data: Vec<u8> },

    /// Sender signals that all chunks have been sent.
    Done { total_chunks: u64 },

    /// Receiver confirms receipt and integrity.
    Ack { sha256: [u8; 32] },

    /// Either side signals a fatal error.
    Error { message: String },

    /// Receiver requests retransmission of a specific counter that was lost.
    Retransmit { counter: u64 },
}

/// Encode any serialisable value to bytes (bincode).
pub fn encode<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::serialize(value)?)
}

/// Decode bytes into any deserialisable value (bincode).
pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> anyhow::Result<T> {
    Ok(bincode::deserialize(bytes)?)
}
