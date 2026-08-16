# RickChat
* **Overview:** A peer-to-peer encrypted UDP chat client. Uses Ed25519 for long-term identity, X25519 for ephemeral session key exchange, a one-directional KDF ratchet for forward secrecy, and RickCrypt (via `rickcrypt`) as the actual symmetric cipher for both the on-disk identity key and every chat packet. Messages are signed before encryption (sign-then-encrypt) so tampering or replay from a non-peer is detectable.

## Constants & Packet Types
* `PKT_HANDSHAKE (0x01)`: identifies a handshake packet
* `PKT_CHAT (0x02)`: identifies a chat packet
* `ED_LEN / X_LEN (32)`: Ed25519 / X25519 key byte lengths
* `SIG_LEN (64)`: Ed25519 signature byte length
* `crypto_executor`: a single-worker `ThreadPoolExecutor` — RickCrypt's global RNG state isn't thread-safe, so all `encrypt`/`decrypt` calls are serialized through this one worker

## Helper Functions
### `h`:
* **Input:** any number of byte strings
* **Working:** feeds each part into a single running BLAKE2b (32-byte digest) hash
* **Output:** 32-byte digest

### `derive_rickcrypt_keys`:
* **Input:** password (string)
* **Working:** BLAKE2b-hashes the password into 24 bytes, then splits it into three little-endian integers
* **Output:** tuple `(k1, k2, nonce)` for use as RickCrypt key material

### `serialize_crypt`:
* **Input:** a RickCrypt "crypt" (list of 4x4 MLX arrays)
* **Working:** writes the chunk count as a 4-byte little-endian int, then flattens each 4x4 array to raw uint64 bytes and concatenates them all
* **Output:** bytes (wire/disk format for a RickCrypt ciphertext)

### `deserialize_crypt`:
* **Input:** bytes
* **Working:** reads the 4-byte chunk count, then walks the buffer in fixed `4*4*8`-byte slices, reshaping each slice into a 4x4 uint64 numpy array and wrapping it as an MLX array
* **Output:** list of MLX arrays (a RickCrypt "crypt")

## Core Cryptography & Identity
### `load_or_create_identity`:
* **Input:** path, password
* **Working:** derives `(k1, k2, nonce)` from the password
  * if the identity file exists: deserialize it, RickCrypt-decrypt it, base64-decode the result, and rebuild the Ed25519 private key from the raw bytes (exits on failure — wrong password or corrupted file)
  * if it doesn't exist: generate a fresh Ed25519 key, base64-encode its raw bytes, RickCrypt-encrypt that string, serialize the resulting crypt to disk, and `chmod 600` the file
* **Output:** `Ed25519PrivateKey` (the long-term identity)

### `Ratchet` (class):
* **Init input:** `chain_key` (bytes) — the root of a one-directional KDF chain
* **`step()` working:**
  * derive `msg_key = h(chain_key, "msg")`
  * advance `chain_key = h(chain_key, "chain")`
  * split `msg_key` into three little-endian integers
* **`step()` output:** tuple `(k1, k2, nonce)` — a fresh, never-reused RickCrypt key for exactly one message, giving forward secrecy (past keys can't be recomputed from the current chain key)

### `get_fingerprint`:
* **Input:** two identity public keys, `id_a`, `id_b`
* **Working:** sorts the two keys so the fingerprint is identical regardless of which side computes it, hashes them together with a `"fingerprint"` label, and hex-formats the first 10 bytes in 4-character groups
* **Output:** human-readable "safety number" string for out-of-band verification (MITM protection)

## Networking
### `ChatProtocol` (class, `asyncio.DatagramProtocol`):
* **Init input:** `queue` — an `asyncio.Queue`
* **`datagram_received` working:** every incoming UDP packet is pushed straight onto the queue with no parsing, keeping the transport callback non-blocking
* **Output:** raw packets available for the async loops to consume via `queue.get()`

## Main Flow (`main`)
### Setup
* **Working:** prompts for local port, peer IP/port, an optional shared "pepper" string mixed into the session root, and the local identity's disk password
* Loads (or creates) the identity via `load_or_create_identity` and opens a UDP socket bound to the local port via `ChatProtocol`

### Handshake phase
* **Working:**
  * generates an ephemeral X25519 keypair and signs the ephemeral public key with the long-term Ed25519 identity
  * builds a handshake packet: `[PKT_HANDSHAKE | identity_pub | ephemeral_pub | signature]`
  * a background task (`handshake_sender`) resends this packet to the peer every second until a handshake is accepted, so the peer's UI never stalls waiting on a slow local user
  * on receiving a peer's handshake packet, verifies the Ed25519 signature over the peer's ephemeral key before accepting it; malformed or unsigned packets are silently dropped
* **Output:** the peer's verified identity public key and ephemeral public key

### Fingerprint verification
* **Working:** computes the safety number via `get_fingerprint`, prints it, and asks the user (via an executor so the background handshake sender keeps running) to confirm it matches the peer's out-of-band
* If the user declines, the exchange is aborted and treated as a possible MITM attempt

### Session derivation
* **Working:**
  * runs X25519 ECDH between the local ephemeral private key and the peer's ephemeral public key to get a shared secret
  * derives a `root` key via `h(shared, sorted_identity_pubs, pepper)`
  * builds two independent `Ratchet` instances — one for sending, one for receiving — each seeded from the root mixed with a directional identity key, so the two peers' send/receive ratchets line up
* **Output:** an established forward-secret session (`send_ratchet`, `recv_ratchet`)

### `decrypt_one`:
* **Input:** sequence number, ciphertext body
* **Working:** deserializes the RickCrypt crypt, advances `recv_ratchet` one step to get this message's key, RickCrypt-decrypts (offloaded to `crypto_executor`), base64-decodes the inner payload, splits it into signature + plaintext, rebuilds the signed payload (`seq | peer_id | own_id | plaintext`), and verifies it against the peer's Ed25519 identity key
* **Output:** decoded plaintext string, or a `"SIGNATURE INVALID"` marker if verification fails

### `receive_loop`:
* **Working:** pulls packets off the queue; re-sends the local handshake if the peer is still mid-handshake; for chat packets, reads the 4-byte sequence number and buffers out-of-order packets in `pending_raw`, draining and decrypting them in order via `decrypt_one` as soon as the expected sequence number is available; prints each decrypted message
* Packets with a sequence number below the next expected value are dropped (replay protection)

### Send loop
* **Working:** reads a line of user input; builds a signed payload (`seq | own_id | peer_id | plaintext`) and signs it with the local Ed25519 identity; base64-encodes `signature + plaintext`; advances `send_ratchet` one step to get a fresh key; RickCrypt-encrypts (offloaded to `crypto_executor`); serializes the crypt and prefixes it with `[PKT_CHAT | seq]`; sends it to the peer and increments the local sequence counter
* **Output:** an encrypted, signed, sequence-numbered UDP packet sent to the peer
