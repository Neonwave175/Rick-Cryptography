import asyncio
import socket
from hashlib import sha512
import numpy as np
import mlx.core as mx
from rickcrypt import decrypt, encrypt


def serialize_crypt(crypt_list):
    parts = [len(crypt_list).to_bytes(4, 'little')]
    for arr in crypt_list:
        parts.append(np.array(arr, dtype=np.uint64).tobytes())
    return b"".join(parts)


def deserialize_crypt(data_bytes):
    if len(data_bytes) < 4:
        raise ValueError("Data too short")
    num_chunks = int.from_bytes(data_bytes[:4], 'little')
    crypt_list = []
    offset = 4
    chunk_size = 4 * 4 * 8
    for _ in range(num_chunks):
        chunk_bytes = data_bytes[offset : offset + chunk_size]
        arr_np = np.frombuffer(chunk_bytes, dtype=np.uint64).reshape(4, 4)
        crypt_list.append(mx.array(arr_np))
        offset += chunk_size
    return crypt_list


def get_nonce_from_msg(msg_str):
    digest = sha512(msg_str.encode()).digest()[:8]
    return int.from_bytes(digest, 'little') & 0xFFFFFFFFFFFFFFFF


async def main():
    local_port = input("Local Port [default 5000]: ").strip()
    local_port = int(local_port) if local_port else 5000

    peer_ip = input("Peer IP [default 127.0.0.1]: ").strip() or "127.0.0.1"

    peer_port = input("Peer Port [default 5001]: ").strip()
    peer_port = int(peer_port) if peer_port else 5001

    k1 = int(input("Key 1 (64-bit int) [default 12345]: ").strip() or 12345)
    k2 = int(input("Key 2 (64-bit int) [default 67890]: ").strip() or 67890)
    current_nonce = int(
        input("Initial Nonce Seed [default 1337]: ").strip() or 1337
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', local_port))
    s.setblocking(False)

    q = asyncio.Queue()
    loop = asyncio.get_running_loop()
    loop.add_reader(s.fileno(), lambda: q.put_nowait(s.recvfrom(65535)))

    state = {"nonce": current_nonce}

    async def receive():
        while True:
            data, _ = await q.get()
            try:
                crypt_list = deserialize_crypt(data)
                msg_text = decrypt(crypt_list, k1, k2, state["nonce"])
                state["nonce"] = get_nonce_from_msg(msg_text)
            except Exception as e:
                msg_text = f"[Decryption Failed: {e}]"
            print(f"\rPeer: {msg_text}\n> ", end="", flush=True)

    asyncio.create_task(receive())

    print(
        f"\n[+] Ready! Listening on port {local_port} -> Sending to {peer_ip}:{peer_port}"
    )
    while True:
        msg = await loop.run_in_executor(None, input, "> ")
        encrypted_list = encrypt(msg, k1, k2, state["nonce"])
        state["nonce"] = get_nonce_from_msg(msg)

        payload = serialize_crypt(encrypted_list)
        s.sendto(payload, (peer_ip, peer_port))


asyncio.run(main())
