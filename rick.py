import math as m
import time as never
from hashlib import sha512

import mlx.core as mx
from blake3 import blake3

BIT_MASK_64 = 0xFFFFFFFFFFFFFFFF
rngseed = 1

def string_to_int(s, n_bytes=8):
    digest = blake3(s.encode("utf-8")).digest(length=n_bytes)
    return int.from_bytes(digest, byteorder="little")

def array_to_int(arr, bits_per_value=64):
    values = arr.reshape(-1).tolist()
    result = 0
    for v in values:
        result = (result << bits_per_value) | (v & ((1 << bits_per_value) - 1))
    return result

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

def array(s, prev, size):
    global rngseed
    n_cells = size * size
    b = s.encode("utf-8")
    seed_val = 0
    for byte_val in b:
        seed_val = ((seed_val << 8) | byte_val) & BIT_MASK_64
    s0 = seed_val
    values = []
    while len(values) < n_cells:
        result = xoroshirosha128plus(s0)
        rngseed = xoroshirosha128plus(prev)
        s0 = result
        for i in range(8):
            if len(values) >= n_cells:
                break
            values.append((result >> (8 * i)) & 0xFF)
    return mx.array(values, dtype=mx.uint8).reshape(size, size)

def make_array(mem, hash_str, matrix, stval):
    global rngseed
    bytes_per_array = matrix * matrix
    mn = mem // bytes_per_array

    mlist = []
    for i in range(mn):
        if len(mlist) == 0:
            arr = array(hash_str, xoroshirosha128plus(stval), matrix)
            rngseed = array_to_int(arr)
        else:
            prev_idx = xoroshirosha128plus(rngseed) % len(mlist)
            prev_val = array_to_int(mlist[prev_idx])
            arr = array(hash_str, prev_val, matrix)
            rngseed = array_to_int(mlist[xoroshirosha128plus(i)%len(mlist)])
        mlist.append(arr)

    return mlist

def step(mls, salt, iter, matrix):
    global rngseed
    hlist = []
    for i in range(iter*8):
        idx = xoroshirosha128plus(salt) % len(mls)
        hlist.append(mls[idx])
        rngseed = xoroshirosha128plus(array_to_int(mls[idx]))

    MOD = 2147483647   # 2^31 - 1, a Mersenne prime -- small enough that MOD*MOD fits safely in int64
    h1 = mx.ones((matrix, matrix), dtype=mx.int64)
    tick = 0
    for h in hlist:
        tick = tick+1
        h_safe = h.astype(mx.int64) + 1
        if tick % 4 == 1:
            h1 = (h1 * h_safe) % MOD
        elif tick % 4 == 2:
            h = h1^h
            arint = (array_to_int(h))
            num_bytes = (arint.bit_length() + 7) // 8 or 1
            h_bytes = arint.to_bytes(num_bytes, byteorder="little")
            digest = blake3(h_bytes).digest(length=matrix * matrix * 8)
            h1 = array(str(digest), xoroshirosha128plus(tick), matrix)
        elif tick % 4 == 3:
            arint = array_to_int(h)
            arint = arint % xoroshirosha128plus(arint)
            if xoroshirosha128plus(arint) % (tick%4) == 1:
                rngseed = xoroshirosha128plus(arint)
                if rngseed % tick == 1:
                    for ne in range(tick%128):
                        rngseed = xoroshirosha128plus(arint)
                        arint = xoroshirosha128plus(arint)
                        if rngseed >= xoroshirosha128plus(arint):
                            rngseed = xoroshirosha128plus(arint)
                            arint = xoroshirosha128plus(arint)
            elif xoroshirosha128plus(arint)%(tick%4) == 2:
                rngseed = xoroshirosha128plus(arint*arint)
            else:
                rngseed = xoroshirosha128plus(m.isqrt(arint*arint*arint))
        else:
            h1 = (h1 ^ h_safe) % MOD
        mx.eval(h1)
        rngseed = xoroshirosha128plus(array_to_int(h))

    return h1

def rick(v, s, t, i, m, ms, l):
    mx.set_default_device(mx.cpu)
    global rngseed
    h = blake3()
    h.update(v.encode("utf-8"))
    h.update(s.encode("utf-8"))
    h.update(t.to_bytes(8, byteorder="little", signed=True))
    h.update(i.to_bytes(8, byteorder="little", signed=True))
    h.update(m.to_bytes(8, byteorder="little", signed=True))
    h.update(ms.to_bytes(8, byteorder="little", signed=True))
    digest = h.digest()
    result = int.from_bytes(digest, byteorder="little")
    rngseed = result
    salt = s
    s = string_to_int(s)
    ar = make_array(m, v, ms, int.from_bytes(digest, byteorder="little"))
    for z in range(t):
        idx = xoroshirosha128plus(s) % len(ar)
        ar[idx] = step(ar, s, i, ms)
        idx = xoroshirosha128plus(s) % len(ar)
        rngseed = xoroshirosha128plus(array_to_int(ar[idx]))
    result = step(ar, s, len(ar), ms)
    result = array_to_int(result)
    byte_length = (result.bit_length() + 7) // 8
    resultb = result.to_bytes(byte_length, byteorder="little")
    resultb = resultb[:l]
    result = int.from_bytes(resultb)
    return ([(f"$rick${result}:{salt}:{t}:{i}:{m}:{ms}"), result])

if __name__ == "__main__":
    mx.set_default_device(mx.cpu)
    time = never.perf_counter()
    print(rick("Never Gonna Give You up", "Never Gonna Let You Down", 24, 8, 4, 2, 128))
    elapsed = never.perf_counter()-time
    print("Time", elapsed)
    print(f"H/S = {1/elapsed}")
