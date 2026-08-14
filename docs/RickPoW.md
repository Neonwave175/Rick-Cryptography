# Rick PoW

* **Overview:** An Argon2-inspired hashing algorithm written in Python, built to be as slow as possible.

## Helper Functions

### `string_to_int`:
* **Input:** String, output byte length
* **Working:** Takes string, converts it to bytes, Blake3 hashes it, converts it back to int and outputs it
* **Output:** Int
