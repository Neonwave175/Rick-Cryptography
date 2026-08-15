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


| key1 | key2 | key1 | key2 |
| nonce | nonce^val3 | nonce | nonce^val3 |
| key1 |val1 |key2 | val2 |
| val3 | val4 | val3 | val4 |
