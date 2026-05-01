# @rachyandco/wormhole-nym-wasm

WebAssembly bindings for the [wormhole-nym](https://github.com/Rachyandco/wormhole-nym) protocol layer — SPAKE2 password-authenticated key exchange, ChaCha20-Poly1305 sealing, and key derivation primitives.

The wasm package exposes the *protocol crypto only*. Transport (the actual mixnet I/O) is left to the consumer — pair it with the [Nym TypeScript SDK](https://www.npmjs.com/package/@nymproject/sdk) on the web side to talk to a Rust CLI peer over Nym.

## Install

```sh
npm install @rachyandco/wormhole-nym-wasm
```

The package is built with `wasm-pack --target bundler`, so it expects a bundler (Vite, webpack, Rollup, esbuild) that understands `import` of `.wasm` modules.

## Quick start — sender side

```js
import {
  wasm_generate_password,
  Spake2SenderState,
  wasm_derive_keys,
  wasm_seal,
} from '@rachyandco/wormhole-nym-wasm';

// 1. Generate a 3-word password to share out-of-band with the receiver.
const password = wasm_generate_password(3); // "fork-road-calm"

// 2. Start SPAKE2. `pake_msg` is sent to the receiver.
const start = Spake2SenderState.start(new TextEncoder().encode(password));
const senderState = start.take_state();
const ourPakeMsg = start.pake_msg();

// 3. Receive the peer's pake message over your transport, then finish.
const sharedSecret = senderState.finish(peerPakeMsg);

// 4. Derive direction-specific keys (32 bytes each).
const keys = wasm_derive_keys(sharedSecret);
const sendKey = keys.slice(0, 32);
const recvKey = keys.slice(32, 64);

// 5. Seal a bincode-encoded Payload with a per-message counter.
const ciphertext = wasm_seal(sendKey, 0n, payloadBytes);
```

## Quick start — receiver side

```js
import { Spake2ReceiverState, wasm_derive_keys, wasm_open } from '@rachyandco/wormhole-nym-wasm';

const start = Spake2ReceiverState.start(new TextEncoder().encode(password));
const receiverState = start.take_state();
const ourPakeMsg = start.pake_msg();

// Send `ourPakeMsg` to the sender, then receive their pake message.
const sharedSecret = receiverState.finish(peerPakeMsg);

const keys = wasm_derive_keys(sharedSecret);
const sendKey = keys.slice(0, 32); // sender's send key = our recv key
const recvKey = keys.slice(32, 64);

// Decrypt; returns bincode-encoded Payload bytes.
const payloadBytes = wasm_open(recvKey, counter, ciphertext);
```

## API

### Word codes

| Function | Returns | Notes |
|---|---|---|
| `wasm_generate_password(num_words: number)` | `string` | Hyphen-joined words from a 361-word list. 3 words ≈ 47M combinations. |

### SPAKE2 (Ed25519Group)

`Spake2SenderState` and `Spake2ReceiverState` are opaque stateful objects. Each is consumed by exactly one `finish()` call.

```ts
class Spake2SenderState {
  static start(password: Uint8Array): StartResult;
  finish(peer_msg: Uint8Array): Uint8Array; // shared secret
}

class StartResult {
  take_state(): Spake2SenderState;
  pake_msg(): Uint8Array;
}

// Same shape for Spake2ReceiverState / ReceiverStartResult.
```

The sender's `pake_msg` must be sent to the receiver and vice versa. Both sides must use the *same* password bytes; if either side fails `finish()`, the password didn't match.

### Key derivation

```ts
function wasm_derive_keys(shared_secret: Uint8Array): Uint8Array;
```

Returns 64 bytes: `[0..32)` is the **send** key (used by the side that talks first in a given direction), `[32..64)` is the **recv** key. Domain separation is fixed: `"wormhole-nym-send"` / `"wormhole-nym-recv"` hashed with SHA-256.

### Seal / open (bincode-encoded `Payload`)

```ts
function wasm_seal(key: Uint8Array, counter: bigint, payload_bytes: Uint8Array): Uint8Array;
function wasm_open(key: Uint8Array, counter: bigint, ciphertext: Uint8Array): Uint8Array;
```

`payload_bytes` must be a bincode encoding of the Rust `Payload` enum. Use these only if you're talking to a CLI peer running the same protocol — otherwise prefer the raw primitives below.

### Raw ChaCha20-Poly1305

```ts
function wasm_encrypt(key: Uint8Array, counter: bigint, plaintext: Uint8Array): Uint8Array;
function wasm_decrypt(key: Uint8Array, counter: bigint, ciphertext: Uint8Array): Uint8Array;
function wasm_sha256(data: Uint8Array): Uint8Array;
```

The counter is a `u64` (passed as JS `BigInt`). Each `(key, counter)` pair must be unique — reusing a counter under the same key breaks confidentiality. The CLI peer increments the counter once per ciphertext.

Keys must be exactly 32 bytes. Errors are thrown as `Error` instances with a descriptive message.

## Compatibility

- This package is bit-compatible with the `wormhole-nym` Rust CLI of the same minor version. SPAKE2 group, key derivation domain separators, AEAD construction, and chunk size all match.
- Counter values, payload encoding, and message ordering are protocol-level concerns handled by the Rust side. If you're building a browser peer for the existing CLI, follow the protocol described in the [main repo README](https://github.com/Rachyandco/wormhole-nym#protocol).

## Versioning

Versions track the Rust workspace. A change to the protocol or any cryptographic constant bumps the minor version and breaks compatibility with older peers.

## License

GPL-3.0-only.
