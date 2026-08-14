## Rick-Cryptography

* **Overview:** A slow cryptography algorithm.

---

### RickPoW

* **Description:**
  * An Argon2-inspired hashing algorithm written in Python.
  * Built to be as slow as possible.

* **Performance Results** *(calculated on an M4 Max with a 14 core CPU and 32 core GPU)*:
  * **Settings `12:3:4:2`:** 23.42 CPU h/s | 10.0 GPU h/s — Small Matmuls so mlx overhead is high
  * **Settings `12:3:128:2`:** 17.43 CPU h/s | 7.11 GPU h/s — Still same result
  * **Settings `12:3:51200:96`:** 0.02 CPU h/s | 0.02 GPU h/s — Large matrix so mlx overhead becomes smaller of an issue
  * **Settings `24:8:4:2`:** 9.42 CPU h/s | 3.15 GPU h/s — More iters

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
* **Documentation:** Read more at `/docs/RickChat`
