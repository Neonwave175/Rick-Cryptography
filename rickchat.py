"""
Secure P2P encrypted UDP chat.
Requires: pip install cryptography mlx numpy --break-system-packages
"""
import asyncio
import base64
import getpass
import hashlib
import os
import struct
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import mlx.core as mx
import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from rickcrypt import decrypt, encrypt

# Serializes rickcrypt calls to prevent module-level global state corruption
crypto_executor = ThreadPoolExecutor(max_workers=1)

PKT_HANDSHAKE = 0x01
PKT_CHAT = 0x02
ED_LEN = X_LEN = 32
SIG_LEN = 64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def h(*parts: bytes) -> bytes:
    d = hashlib.blake2b(digest_size=32)
    for p in parts:
        d.update(p)
    return d.digest()


def derive_rickcrypt_keys(password: str) -> tuple[int, int, int]:
    """Derives a deterministic (k1, k2, nonce) from a password."""
    d = hashlib.blake2b(password.encode(), digest_size=24).digest()
    return (
        int.from_bytes(d[0:8], "little"),
        int.from_bytes(d[8:16], "little"),
        int.from_bytes(d[16:24], "little")
    )


def serialize_crypt(crypt_list: list) -> bytes:
    parts = [len(crypt_list).to_bytes(4, "little")]
    for arr in crypt_list:
        parts.append(np.array(arr, dtype=np.uint64).tobytes())
    return b"".join(parts)


def deserialize_crypt(data_bytes: bytes) -> list:
    if len(data_bytes) < 4:
        raise ValueError("Data too short")
    num_chunks = int.from_bytes(data_bytes[:4], "little")
    crypt_list = []
    offset = 4
    chunk_size = 4 * 4 * 8
    for _ in range(num_chunks):
        chunk_bytes = data_bytes[offset: offset + chunk_size]
        arr_np = np.frombuffer(chunk_bytes, dtype=np.uint64).reshape(4, 4)
        crypt_list.append(mx.array(arr_np))
        offset += chunk_size
    return crypt_list


# ---------------------------------------------------------------------------
# Core Cryptography & Identity
# ---------------------------------------------------------------------------

def load_or_create_identity(path: Path, password: str) -> Ed25519PrivateKey:
    """Loads or creates the long-term Ed25519 identity, encrypted at rest via rickcrypt."""
    k1, k2, nonce = derive_rickcrypt_keys(password)

    if path.exists():
        try:
            crypt_list = deserialize_crypt(path.read_bytes())
            b64_str = decrypt(crypt_list, k1, k2, nonce)
            raw = base64.b64decode(b64_str)
            return Ed25519PrivateKey.from_private_bytes(raw)
        except Exception as e:
            print(f"[!] Failed to decrypt identity (wrong password?): {e}")
            sys.exit(1)

    print("[i] Generating new identity key...")
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Encrypt and save
    b64_str = base64.b64encode(raw).decode("ascii")
    encrypted_list = encrypt(b64_str, k1, k2, nonce)
    path.write_bytes(serialize_crypt(encrypted_list))
    os.chmod(path, 0o600)
    return key


class Ratchet:
    """One-directional KDF chain for forward secrecy."""
    def __init__(self, chain_key: bytes):
        self.chain_key = chain_key

    def step(self):
        msg_key = h(self.chain_key, b"msg")
        self.chain_key = h(self.chain_key, b"chain")
        return (
            int.from_bytes(msg_key[0:8], "little"),
            int.from_bytes(msg_key[8:16], "little"),
            int.from_bytes(msg_key[16:24], "little")
        )


def get_fingerprint(id_a: bytes, id_b: bytes) -> str:
    lo, hi = sorted([id_a, id_b])
    hexs = h(lo, hi, b"fingerprint")[:10].hex()
    return " ".join(hexs[i:i + 4] for i in range(0, len(hexs), 4))


# ---------------------------------------------------------------------------
# Async UDP Protocol
# ---------------------------------------------------------------------------

class ChatProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    def datagram_received(self, data: bytes, addr: tuple):
        self.queue.put_nowait(data)


async def main():
    print("--- Secure P2P Chat Setup ---")
    local_port = int(input("Local Port [default 5000]: ").strip() or 5000)
    peer_ip = input("Peer IP [default 127.0.0.1]: ").strip() or "127.0.0.1"
    peer_port = int(input("Peer Port [default 5001]: ").strip() or 5001)
    pepper = input("Optional extra shared pepper (blank is fine): ").strip()
    disk_pw = getpass.getpass("Local Identity Password: ")

    # Identity
    identity_path = Path(f"identity_{local_port}.key")
    identity = load_or_create_identity(identity_path, disk_pw)
    identity_pub = identity.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(f"[i] Identity active: {identity_pub.hex()[:16]}...")

    # Ephemeral Keypair (Signed)
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    eph_sig = identity.sign(eph_pub)

    # Networking Setup
    loop = asyncio.get_running_loop()
    q = asyncio.Queue()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: ChatProtocol(q),
        local_addr=("0.0.0.0", local_port)
    )

    def sendto_peer(data: bytes):
        transport.sendto(data, (peer_ip, peer_port))

    # --- Handshake Phase ---
    handshake_pkt = bytes([PKT_HANDSHAKE]) + identity_pub + eph_pub + eph_sig
    handshake_done = asyncio.Event()

    # Background task to continuously ping the peer so we don't stall their UI
    async def handshake_sender():
        while not handshake_done.is_set():
            sendto_peer(handshake_pkt)
            await asyncio.sleep(1.0)

    bg_sender = asyncio.create_task(handshake_sender())

    print("[+] Waiting for peer handshake...")
    peer_identity_pub, peer_eph_pub = None, None

    while not peer_identity_pub:
        data = await q.get()
        if not data or data[0] != PKT_HANDSHAKE or len(data[1:]) != ED_LEN + X_LEN + SIG_LEN:
            continue

        body = data[1:]
        r_id, r_eph, r_sig = body[:ED_LEN], body[ED_LEN:ED_LEN + X_LEN], body[ED_LEN + X_LEN:]

        try:
            Ed25519PublicKey.from_public_bytes(r_id).verify(r_sig, r_eph)
            peer_identity_pub, peer_eph_pub = r_id, r_eph
        except InvalidSignature:
            pass # ignore tampered packets

    # --- Fingerprint Verification ---
    fp = get_fingerprint(identity_pub, peer_identity_pub)
    print("\n" + "=" * 60)
    print("  SAFETY NUMBER -- verify this OUT OF BAND before trusting:")
    print(f"\n      {fp}\n")
    print("=" * 60)

    def ask_yn():
        return input("Does this match your peer? [y/N]: ").strip().lower()

    # Call input in an executor so the bg_sender task keeps responding in the background
    if (await loop.run_in_executor(None, ask_yn)) != "y":
        print("[!] Aborting. Treat this as a possible MITM.")
        bg_sender.cancel()
        return

    # User accepted, stop broadcasting handshakes
    handshake_done.set()

    # --- Session Derivation ---
    shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(peer_eph_pub))
    id_lo, id_hi = sorted([identity_pub, peer_identity_pub])
    root = h(shared, id_lo, id_hi, pepper.encode())

    send_ratchet = Ratchet(h(root, identity_pub, b"send"))
    recv_ratchet = Ratchet(h(root, peer_identity_pub, b"send"))
    print("[+] Verified. Forward-secret session established.\n")

    # --- Receive Loop ---
    state = {"send_seq": 0, "recv_seq_expected": 0}
    pending_raw = {}

    async def decrypt_one(seq: int, ct_body: bytes) -> str:
        crypt_list = deserialize_crypt(ct_body)
        k1, k2, nonce = recv_ratchet.step()

        inner_str = await loop.run_in_executor(crypto_executor, decrypt, crypt_list, k1, k2, nonce)
        inner_bytes = base64.b64decode(inner_str)
        sig, plaintext = inner_bytes[:SIG_LEN], inner_bytes[SIG_LEN:]

        # Verify Sign-Then-Encrypt binding
        payload = struct.pack("<I", seq) + peer_identity_pub + identity_pub + plaintext
        try:
            Ed25519PublicKey.from_public_bytes(peer_identity_pub).verify(sig, payload)
            return plaintext.decode(errors="replace")
        except InvalidSignature:
            return "[!! SIGNATURE INVALID -- dropped message !!]"

    async def receive_loop():
        while True:
            data = await q.get()
            if not data:
                continue

            if data[0] == PKT_HANDSHAKE:
                # The peer is still handshaking (maybe they took longer to press 'y')
                sendto_peer(handshake_pkt)
                continue

            if data[0] != PKT_CHAT or len(data) < 5:
                continue

            seq = int.from_bytes(data[1:5], "little")
            if seq < state["recv_seq_expected"]:
                continue

            pending_raw[seq] = data[5:]
            while state["recv_seq_expected"] in pending_raw:
                nxt_seq = state["recv_seq_expected"]
                raw_ct = pending_raw.pop(nxt_seq)
                try:
                    text = await decrypt_one(nxt_seq, raw_ct)
                except Exception as e:
                    text = f"[Decryption Failed: {e}]"

                print(f"\rPeer: {text}\n> ", end="", flush=True)
                state["recv_seq_expected"] += 1

    asyncio.create_task(receive_loop())

    # --- Send Loop ---
    while True:
        msg = await loop.run_in_executor(None, input, "> ")
        if not msg:
            continue

        seq = state["send_seq"]
        plaintext_bytes = msg.encode()

        # Sign-Then-Encrypt binding
        payload = struct.pack("<I", seq) + identity_pub + peer_identity_pub + plaintext_bytes
        sig = identity.sign(payload)
        inner_str = base64.b64encode(sig + plaintext_bytes).decode("ascii")

        k1, k2, nonce = send_ratchet.step()
        try:
            encrypted_list = await loop.run_in_executor(crypto_executor, encrypt, inner_str, k1, k2, nonce)
            pkt = bytes([PKT_CHAT]) + seq.to_bytes(4, "little") + serialize_crypt(encrypted_list)
            sendto_peer(pkt)
            state["send_seq"] += 1
        except Exception as e:
            print(f"[!] Send failed: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting.")
