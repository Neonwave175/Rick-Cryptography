# RickCrypt

* **Overview:** An XChaCha20 inspired encryption algorithm that uses RickPoW to generate its origin array to slow down brute forcing.

## Helper Functions

### `atpos`:
* **Input:** array, x, y, value to be insterted
* **Working:** puts a value at the position
* **Output** MLX array

### `c2a`:
* **Input:** List
* **Working:** uses atpos to put each item in a place int he list
* **Output:** MLX array

### `chunkify`:
* **Input:** string
* **Working:** encode input string into bytes, chop them into 16 byte segments and put them in a list
* **Output:** List of 16-byte chunks

### `chunkyarray`:
* **Input:** String
* **Working:** uses `chunkify` to chop the string and uses `c2a` to make those chunks into a list of arrays
* **Output:** list of arrays

## RNG

### `xoroshirosha128plus`:
* **Input:** Seed0
* **Working:** This is not a textbook Xoroshiro+ it has a extra sha step
  * set global rng seed to sha512 of s0
  * set seed1 to global seed and then update it
  * Rotate s0 by 24 and set that to s0 rot
  * update s0 to a mix of seed1 and s0 rot
  * rotate s1 by 37
  * Sha512 s1^s0 and set that to s1
  * return s1+s0
* **Why extra Sha512:** Xoroshiro128+ has been cracked and reversed so in theory if the hacker gets a rng number, they can reverse it to one chunk. Also, it slows down the hacker
* **Output:** 64 bit int

## Main functions

### `createar`:
* **Inputs:** key1, key2, nonce
* **Working:** Creates a 4x4 array from the input values
  * val 1 is the xoroshirosha of nonce
  * val 2 is also the same, but since xoroshirosha updates the global rng internally, a different value will pop out
  * val 3 is a blake3 of a rick of xoroshirosha of nonce ^ key1
  * val 4 is basically the same as val 3 but instead of key1 it is key2
  * Then we package it in a array with this format

  | C1 | C2 | C3 | C4 |
  |------|------|------|------|
  | key1 | key2 | key1 | key2 |
  | nonce | nonce^val3 | nonce | nonce^val3 |
  | key1 | val1 | key2 | val2 |
  | val3 | val4 | val3 | val4 |

* **Output:** MLX array

### `arx`:
* **Inputs:** ara, arb, rev
* **Working:** This is not the textbook arx, just add, rotate and xor. You can actually crack the keys if I did that due to a error in the logic
  * ar(output array) is set to ara
  * rotate ar by 24
  * add ar and arb
  * xor ara and ar
  * xor arb and ar
  * Hash this entire thing using blake3
  * return ar
* **Output:** moddified array

### `encrypt_bytes`
* **Input:** bytes, key1, key2, nonce, rounds
* **Working:** encrypting logic
  * Take in the value, add 8 byte paddings on both sides to reduce the cracking of known values
  * Convert it into chunks
  * Use create ar to create the origin key
  * Then use arx to create a new value based on the origin, then xor the current chunk with the arx of the key
  * For the next round, use the previous arx and arx it again to create a new kay, xor this and repeat this process untill all the chunks are encrypted
* **Output:** List of MLX arrays

### `decrypt_bytes`
* **Input:** bytes, key1, key2, nonce, rounds
* **Working:** encrypting logic
  * Take the list of encrypted values
  * Use create ar to create the origin key
  * Then use arx to create a new value based on the origin, then xor the current chunk with the arx of the key
  * For the next round, use the previous arx and arx it again to create a new kay, xor this and repeat this process untill all the chunks are decrypted
  * Remove the padding
* **Output:** Bytes

## Packaging functions:

### `encrypt`:
Takes in a string, outputs crypt

### `encrypt`:
Takes in a crypt, outputs string

### `encrypt_file`:
Takes in a file, saves the output as a .rickcrypt file

### `decrypt_file`:
Takes in a .rickcrypt file, saves the output as a file
