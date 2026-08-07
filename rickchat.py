import asyncio
import socket
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
        chunk_bytes = data_bytes[offset: offset + chunk_size]
        arr_np = np.frombuffer(chunk_bytes, dtype=np.uint64).reshape(4, 4)
        crypt_list.append(mx.array(arr_np))
        offset += chunk_size
    return crypt_list


def nonce_for(base, seq):
    # Counter-derived nonce: depends only on the seed + this message's
    # sequence number, never on the plaintext of a previous message.
    # This means a dropped or out-of-order packet can never desync the
    # chain, and two directions can never race each other.
    return (base + seq) & 0xFFFFFFFFFFFFFFFF


async def main():
    local_port = input("Local Port [default 5000]: ").strip()
    local_port = int(local_port) if local_port else 5000
    peer_ip = input("Peer IP [default 127.0.0.1]: ").strip() or "127.0.0.1"
    peer_port = input("Peer Port [default 5001]: ").strip()
    peer_port = int(peer_port) if peer_port else 5001
    k1 = int(input("Key 1 (64-bit int) [default 12345]: ").strip() or 12345)
    k2 = int(input("Key 2 (64-bit int) [default 67890]: ").strip() or 67890)
    seed = int(input("Nonce Seed [default 1337]: ").strip() or 1337)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', local_port))
    s.setblocking(False)

    q = asyncio.Queue()
    loop = asyncio.get_running_loop()
    loop.add_reader(s.fileno(), lambda: q.put_nowait(s.recvfrom(65535)))

    # Independent sequence counters per direction. No shared mutable
    # nonce state between the send loop and receive() -> no race.
    state = {"send_seq": 0, "recv_seq_expected": 0}

    # Small out-of-order buffer in case UDP reorders packets and you
    # want in-order printing. Optional -- comment out if you don't care.
    pending = {}

    def print_line(text):
        print(f"\rPeer: {text}\n> ", end="", flush=True)

    async def receive():
        while True:
            data, _ = await q.get()
            seq = None
            try:
                if len(data) < 4:
                    raise ValueError("Packet too short")
                seq = int.from_bytes(data[:4], 'little')
                body = data[4:]
                crypt_list = deserialize_crypt(body)
                n = nonce_for(seed, seq)
                print(f"\r[debug] recv seq={seq} nonce={n} seed={seed}\n> ", end="", flush=True)
                # Run the (slow) decrypt off the event loop so it can't
                # block processing of the next incoming/outgoing packet.
                msg_text = await loop.run_in_executor(
                    None, decrypt, crypt_list, k1, k2, n
                )
            except Exception as e:
                msg_text = f"[Decryption Failed: {e}]"

            if seq is None:
                # Couldn't even read a seq number -- nothing to order,
                # just print immediately.
                print_line(msg_text)
                continue

            # Buffer + print in seq order. Failures still occupy their
            # slot so one bad/undecryptable packet can't permanently
            # stall every later message behind it.
            pending[seq] = msg_text
            while state["recv_seq_expected"] in pending:
                nxt = state["recv_seq_expected"]
                print_line(pending.pop(nxt))
                state["recv_seq_expected"] += 1

    asyncio.create_task(receive())

    print(
        f"\n[+] Ready! Listening on port {local_port} -> Sending to {peer_ip}:{peer_port}"
    )

    send_seq = 0
    while True:
        msg = await loop.run_in_executor(None, input, "> ")
        n = nonce_for(seed, send_seq)
        print(f"[debug] send seq={send_seq} nonce={n} seed={seed}")
        # Run encrypt off the event loop too -- this is what was
        # letting a slow encrypt starve the receive() task before.
        encrypted_list = await loop.run_in_executor(
            None, encrypt, msg, k1, k2, n
        )
        payload = send_seq.to_bytes(4, 'little') + serialize_crypt(encrypted_list)
        s.sendto(payload, (peer_ip, peer_port))
        send_seq += 1


if __name__ == "__main__":
    asyncio.run(main())
