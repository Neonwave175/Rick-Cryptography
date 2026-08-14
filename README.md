# Rick-Cryptography
a slow cryptography algorithm

## RickPoW
A argon2 inspired hashing algorithm written in python
This thing is built to be as slow as possible

Performance results (calculated on a M4 Max with a 14 core CPU and 32 core GPU)
|CPU h/s|GPU h/s|Settings|Comments|
|-------|--------|--------|--------|
|23.42|10.0|12:3:4:2|Small Matmuls so mlx overhead is high|
|17.43|7.11|12:3:128:2|Still same result|
|0.02|0.02|12:3:51200:96|Large matrix so mlx overhead becomes smaller of a issue|
|9.42|3.15|24:8:4:2|More iters|


It is designed to not be multi-threadable by making each step rely on the previous. This helps in slowing down brute forcing. It is also very configurable with settings for time, iterations, base memory, matrix size, and length
Read more in the /docs/RickPoW.md

## RickCrypt
This is a encryption algorithm that uses RickPoW to generate the origin matrix and them uses ARX to generate the key stream.
It puts the input value into chunks then xors each value with the output array of the ARX like Xchacha
Then it returns matrixes as the output

Since this uses 2xRickPoW to generate the origin array, the generation of the origin array is slow.
This is delebrate to reduce brute forcing

Read more at /docs/RickCrypt.md

## RickChat
This is a rick based chatting app that is based of UDP so there is no Client<->Server<->Client, only Peer<->Peer to reduce vulnarabilities
It uses rick crypt so is very slow (3-6 seconds per message on Lo in a MacBook Pro M4 Max) but depending on the use case, this can be adjusted by changing the settings in RickCrypt

Read more at /docs/RickChat.md


### License
Dual licenses under Apache 2.0 and GNU GPL v3
>This is just a recommendation:
I believe software (free or paid) should be open source.
Whatever you make with this should also be open source is what I hope you will do
Again, this is not legally binding but please make any personal project you make with this open source,
or at least, don't obscurity the code


Thank You
Bhuvan Jeyaganesan
