from hashlib import sha512
from os import urandom
from time import perf_counter

import mlx.core as mx
import numpy as np
from blake3 import blake3
from rick import rick

rngseed = 0
BIT_MASK_64 = 0xFFFFFFFFFFFFFFFF

def xoroshirosha128plus(s0):
    global rngseed
    rngseed ^= int.from_bytes(sha512((s0 & BIT_MASK_64).to_bytes(8, 'little')).digest()[:8],'little')
    if rngseed == 0:
        rngseed = 1
    s1 = rngseed
    rngseed = (s0 + s1) & BIT_MASK_64
    s1 ^= s0
    s0_rot = ((s0 << 24) | (s0 >> (64 - 24))) & BIT_MASK_64
    s0 = (s0_rot ^ s1 ^ (s1 << 16)) & BIT_MASK_64
    s1 = ((s1 << 37) | (s1 >> (64 - 37))) & BIT_MASK_64
    s1 = int.from_bytes(sha512((s0 ^ s1).to_bytes(8, 'little')).digest()[:8], 'little') & BIT_MASK_64
    result = (s0 + s1) & BIT_MASK_64
    return result

def atpos(arr, x, y, val):
    arr[x, y] = val
    return arr

def createar(key1, key2, nonce):
    val1 = xoroshirosha128plus(nonce) & 0xFFFFFFFFFFFFFFFF
    val2 = xoroshirosha128plus(nonce) & 0xFFFFFFFFFFFFFFFF
    val3 = int.from_bytes(blake3(str(rick(str(xoroshirosha128plus(nonce ^ key2) & 0xFFFFFFFFFFFFFFFF), str(key1 ^ nonce), 12, 3, int(0.1*(1.049*10**6)), 8, 8)[1]).encode()).digest(length=8),'little')
    val4 = int.from_bytes(blake3(str(rick(str(xoroshirosha128plus(nonce ^ key2) & 0xFFFFFFFFFFFFFFFF), str(key2 ^ nonce), 12, 3, int(0.1*(1.049*10**6)), 8, 8)[1]).encode()).digest(length=8),'little')
    ar = mx.array([
        [key1, key2, key1, key2],
        [nonce, nonce, nonce, nonce],
        [key1, val1, key2, val2],
        [val3, val4, val3, val4],
    ], dtype=mx.uint64)
    return ar

def arx(ara, arb, rev):
    ar = ara
    for _ in range(rev):
        ar = ar << 24 | ar >> (64 - 24)
        ar = ar + arb
        ar = ara ^ ar
        ar = arb ^ ar

        # --- batched hash step ---
        arr_np = np.array(ar).astype('<u8')
        flat = arr_np.reshape(-1)
        data = flat.tobytes()
        digest = blake3(data).digest(length=128)
        new_flat = np.frombuffer(digest, dtype='<u8')
        ar = mx.array(new_flat.reshape(4, 4))
    return ar

def arx_np(ara, arb, rev):
    # Ensure they are numpy arrays of uint64
    ara = np.asarray(ara, dtype=np.uint64)
    arb = np.asarray(arb, dtype=np.uint64)
    ar = ara.copy()
    for _ in range(rev):
        ar = (ar << np.uint64(24)) | (ar >> np.uint64(40))
        ar = ar + arb
        ar = ara ^ ar
        ar = arb ^ ar

        data = ar.tobytes()
        digest = blake3(data).digest(length=128)
        ar = np.frombuffer(digest, dtype='<u8').copy().reshape(4, 4)
    return ar

def c2a(chunkv):
    chunka = mx.ones((4, 4))
    for tick, chunk in enumerate(chunkv):
        chunka = atpos(chunka, tick // 4, tick % 4, chunk)
    return mx.array(chunka, dtype=mx.uint8)

def chunkify(s):
    b = s.encode()
    chunks = []
    for i in range(0, len(b), 16):
        chunks.append(list(b[i:i+16]))
    return chunks

def chunkyarray(s):
    s = chunkify(s)
    arrays = []
    for chunks in s:
        arrays.append(c2a(chunks))
    return(arrays)

def encrypt_bytes(b, k1, k2, n):
    global rngseed
    rngseed = 0
    val_bytes = urandom(8).hex().encode('utf-8') + b + urandom(8).hex().encode('utf-8')
    chunks = []
    for i in range(0, len(val_bytes), 16):
        chunks.append(list(val_bytes[i:i+16]))
    arrayls = []
    for chunks_list in chunks:
        arrayls.append(c2a(chunks_list))
    crypt = []
    origin = createar(k1, k2, n)
    prevx = origin
    for array in arrayls:
        origin = arx(origin, prevx, 1024)
        newit = array.astype(mx.uint64) ^ origin
        mx.eval(newit)
        crypt.append(newit)
    return crypt

def encrypt(v, k1, k2, n):
    return encrypt_bytes(v.encode('utf-8'), k1, k2, n)

def decrypt_bytes(crypt, k1, k2, n):
    global rngseed
    rngseed = 0
    origin = createar(k1, k2, n)
    prevx = origin
    decrypted_bytes = []
    for array in crypt:
        origin = arx(origin, prevx, 1024)
        newit = (array ^ origin).astype(mx.uint8)
        mx.eval(newit)
        arr_np = np.array(newit)
        decrypted_bytes.extend(arr_np.flatten().tolist())
    full_bytes = bytes(decrypted_bytes)
    full_bytes = full_bytes.rstrip(b'\x01')
    message_bytes = full_bytes[16:-16]
    return message_bytes

def decrypt(crypt, k1, k2, n):
    return decrypt_bytes(crypt, k1, k2, n).decode('utf-8')

def encrypt_file(input_path, output_path, k1, k2, n):
    global rngseed
    rngseed = 0

    origin = np.array(createar(k1, k2, n), dtype=np.uint64)
    prevx = origin.copy()

    prefix = urandom(16)

    def chunk_generator():
        yield prefix
        with open(input_path, 'rb') as f:
            while True:
                chunk = f.read(16)
                if not chunk:
                    break
                if len(chunk) == 16:
                    yield chunk
                else:
                    padding_len = 16 - len(chunk)
                    yield chunk + (b'\x01' * padding_len)
        yield urandom(16)

    # Local variable lookups for speed
    local_arx_np = arx_np

    with open(output_path, 'wb') as out_f:
        buffer = bytearray()
        for chunk in chunk_generator():
            origin = local_arx_np(origin, prevx, 10)

            origin_u8 = origin.astype(np.uint8)
            chunk_arr = np.frombuffer(chunk, dtype=np.uint8).reshape(4, 4)
            encrypted_chunk = chunk_arr ^ origin_u8

            buffer.extend(encrypted_chunk.tobytes())
            if len(buffer) >= 1024 * 1024:  # Write in 1MB chunks
                out_f.write(buffer)
                buffer.clear()
        if buffer:
            out_f.write(buffer)

def decrypt_file(input_path, output_path, k1, k2, n):
    global rngseed
    rngseed = 0

    origin = np.array(createar(k1, k2, n), dtype=np.uint64)
    prevx = origin.copy()

    # Local variable lookups for speed
    local_arx_np = arx_np

    with open(input_path, 'rb') as in_f, open(output_path, 'wb') as out_f:
        buffer = []
        write_buffer = bytearray()
        is_first = True

        while True:
            chunk = in_f.read(16)
            if not chunk:
                break

            origin = local_arx_np(origin, prevx, 10)

            origin_u8 = origin.astype(np.uint8)
            chunk_arr = np.frombuffer(chunk, dtype=np.uint8).reshape(4, 4)
            decrypted_chunk = (chunk_arr ^ origin_u8).tobytes()

            if is_first:
                is_first = False
                continue

            buffer.append(decrypted_chunk)
            if len(buffer) > 2:
                # Pop the oldest block and write it (not the last content block or suffix)
                oldest = buffer.pop(0)
                write_buffer.extend(oldest)
                if len(write_buffer) >= 1024 * 1024:
                    out_f.write(write_buffer)
                    write_buffer.clear()

        # We are at the end of the stream.
        # buffer[0] is the last content block (end of content + padding)
        # buffer[1] is the suffix block (to be discarded)
        if len(buffer) >= 2:
            last_content = buffer[0].rstrip(b'\x01')
            write_buffer.extend(last_content)

        if write_buffer:
            out_f.write(write_buffer)

if __name__ == "__main__":
    ran = int.from_bytes(urandom(8), 'little')
    ran2 = int.from_bytes(urandom(8), 'little')
    print("Encrypting")
    start = perf_counter()
    encrypt_file("examples/Steve.jpg", "examples/Steve.rickcrypt", ran, ran2, 12345)
    print(perf_counter()-start)
    print("Decrypting")
    start = perf_counter()
    decrypt_file("examples/Steve.rickcrypt", "examples/SteveDec.jpg", ran, ran2, 12345)
    print(perf_counter()-start)
