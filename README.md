## Rick-Cryptography

* **Overview:** A slow cryptography algorithm.

---

### RickPoW

* **Description:** An Argon2-inspired hashing algorithm written in Python, built to be as slow as possible.
* **Performance Results** *(calculated on an M4 Max with a 14 core CPU and 32 core GPU)*:

| CPU h/s | GPU h/s | Settings | Comments |
| ------- | ------- | -------- | -------- |
| 23.42 | 10.0 | 12:3:4:2 | Small Matmuls so mlx overhead is high |
| 17.43 | 7.11 | 12:3:128:2 | Still same result |
| 0.02 | 0.02 | 12:3:51200:96 | Large matrix so mlx overhead becomes smaller of a issue |
| 9.42 | 3.15 | 24:8:4:2 | More iters |

* **Key Features & Design:**
  * Designed to **not be multi-threadable** by making each step rely on the previous, helping slow down brute forcing.
  * Highly configurable with settings for **time, iterations, base memory, matrix size, and length**.
* **Documentation:** Read more in `/docs/RickPoW.md`

---

### RickCrypt

* **Description:** An encryption algorithm that uses RickPoW to generate the origin matrix and ARX to generate the key stream.
* **Mechanism:**
  * Chunks the input value and XORs each value with the output array of the ARX (similar to XChaCha).
  * Returns matrixes as the output.
* **Security & Performance:**
  * Uses `2xRickPoW` to generate the origin array, making origin array generation intentionally slow.
  * Deliberately designed this way to reduce brute forcing.
* **Documentation:** Read more at `/docs/RickCrypt.md`

---

### RickChat

* **Description:** A Rick-based chatting application built on UDP with **Peer-to-Peer** architecture (no `Client <-> Server <-> Client` routing) to reduce vulnerabilities.
* **Performance & Tuning:**
  * Uses RickCrypt, making it very slow (**3–6 seconds per message** on local host on a MacBook Pro M4 Max).
  * Settings in RickCrypt can be adjusted depending on the specific use case.
* **Documentation:** Read more at `/docs/RickChat.md`



## AI note:
* I wrote most of the code here, Claude and Gemini only wrote the `rickchat.py` and its docs
* All other docs and code was written by me
