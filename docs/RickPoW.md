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

### `array`:
* **Input:** string, previous array number, array size
* **Working:** Converts a string to a array of a specified size
  * encodes the given string into bytes
  * creates a int variable of the entire contents
  * Uses that values as a seed and generates random numbers and adds them to a list
  * Then it takes that list, reshapes it into a square and outputs it
* **Output:** array generated from the input string

### `make_array`:
* **Input:** memory ammount of the list, string input, matrix size, start value
* **Working:** makes a list of arrays from a string that fits in the given memory
  * Finds out the number of matrixes that can fit in a array of that length
  * start with creating a array using the `array` function with the input of the string and the rnged stval
  * for the next arrays, use the previous arrays as a stval by passing it through `array_to_int`
  * Return a list with the generated arrays
* **Output:** List of arrays

### `step`
* **Input:** matrix list, salt, iterations, matrix size
* **Working:** A single step with hashing, matmuls, XORs and lots of if statements
  * Pick a few matrixes from the list using the rng
  * Put them in a list
  * Create a new array with ones for the specified size, this is the matrix that will be modified
  * In a loop, if tick % 4 is 1, then run a matmul with one matrix and the output matrix
  * If it is 2, run a blake3 hash on the output matrix ^ random matrix and then set output matrix to it
  * If it is 3, then run a bunch of if statements that update the rng seed to force the user to run it on the CPU to get the branch prediction advantage
  * Or else just do the first step
  * Return h1 and update the rng seed
* **Output:** one single array

## Final Rick function (`rick`)
* **Input:** value, salt, time cost, iteration, memory, matrix size, length
* **Working:** Main hashing function
  * Set default device to CPU
  * Mix all the input values using blake3 and return a int
  * Set the rngseed to the value
  * Create a int version of salt
  * Create a array list
  * Repeat step on the array for 't' rounds while updating rng seed every time
  * Squash the entire list into one matrix by running step with the iter set to the length of the output list (Turns out, this takes 1/3 ish of the time)
  * Convert this into a int using `array_to_int` and then trim it to the dezired length
  * Finally, return 2 versions: first one fully formatted with all settings, hash and salt in one string and another with just the hash output int
