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
    val3 = int.from_bytes(blake3(str(rick(str(xoroshirosha128plus(nonce ^ key1) & 0xFFFFFFFFFFFFFFFF), str(key1 ^ nonce), 12, 3, int(0.1*(1.049*10**6)), 8, 8)[1]).encode()).digest(length=8),'little')
    val4 = int.from_bytes(blake3(str(rick(str(xoroshirosha128plus(nonce ^ key2) & 0xFFFFFFFFFFFFFFFF), str(key2 ^ nonce), 12, 3, int(0.1*(1.049*10**6)), 8, 8)[1]).encode()).digest(length=8),'little')
    ar = mx.array([
        [key1, key2, key1, key2],
        [nonce, nonce^val3, nonce, nonce^val4],
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
    b = s.encode() if isinstance(s, str) else s
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

def encrypt_bytes(b, k1, k2, n, r):
    global rngseed
    rngseed = 0
    val_bytes = urandom(8).hex().encode('utf-8') + b + urandom(8).hex().encode('utf-8')
    arrayls = chunkyarray(val_bytes)
    crypt = []
    origin = createar(k1, k2, n)
    prevx = origin
    for array in arrayls:
        origin = arx(origin, prevx, r)
        newit = array.astype(mx.uint64) ^ origin
        mx.eval(newit)
        crypt.append(newit)
    return crypt

def encrypt(v, k1, k2, n):
    return encrypt_bytes(v.encode('utf-8'), k1, k2, n, 1024)

def decrypt_bytes(crypt, k1, k2, n, r):
    global rngseed
    rngseed = 0
    origin = createar(k1, k2, n)
    prevx = origin
    decrypted_bytes = bytearray()
    for array in crypt:
        origin = arx(origin, prevx, r)
        newit = (array ^ origin).astype(mx.uint8)
        mx.eval(newit)
        decrypted_bytes.extend(np.array(newit).flatten())
    return bytes(decrypted_bytes).rstrip(b'\x01')[16:-16]

def decrypt(crypt, k1, k2, n):
    return decrypt_bytes(crypt, k1, k2, n, 1024).decode('utf-8')

def encrypt_file(input_path, output_path, k1, k2, n):
    with open(input_path, 'rb') as f:
        data = f.read()
    crypt = encrypt_bytes(data, k1, k2, n, 16)
    with open(output_path, 'wb') as f:
        for array in crypt:
            f.write(np.array(array, dtype=np.uint64).tobytes())

def decrypt_file(input_path, output_path, k1, k2, n):
    crypt = []
    with open(input_path, 'rb') as f:
        while True:
            chunk = f.read(128)  # 4x4 uint64 = 128 bytes per crypt block
            if not chunk:
                break
            crypt.append(mx.array(np.frombuffer(chunk, dtype=np.uint64).reshape(4, 4)))
    with open(output_path, 'wb') as f:
        f.write(decrypt_bytes(crypt, k1, k2, n, 16))

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
