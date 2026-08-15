# Rick PoW

* **Overview:** An Argon2-inspired hashing algorithm written in Python, built to be as slow as possible.

## Helper Functions

### `string_to_int`:
* **Input:** String, output byte length
* **Working:** Takes string, converts it to bytes, Blake3 hashes it, converts it back to int and outputs it
* **Output:** Int

### `array_to_int`:
* **Input:** Mlx array, bytes per digit
* **Working:** puts the first digit, puts a 0, then it replaces that 0 with the next digit and so on till the end of the array
* **Output:** Int

## RNG

### `xoroshirosha128plus`
* **Input:** Seed0
* **Working:** This is not a textbook Xoroshiro+ it has a extra sha step
  * XOR s0 by globalseed
  * set seed1 to global seed and then update it
  * Rotate s0 by 24 and set that to s0 rot
  * update s0 to a mix of seed1 and s0 rot
  * rotate s1 by 37
  * Sha512 s1^s0 and set that to s1
  * return s1+s0
* **Why extra Sha512:** Xoroshiro128+ has been cracked and reversed so in theory if the hacker gets a rng number, they can reverse it to one chunk
* **Output:** 64 bit int
