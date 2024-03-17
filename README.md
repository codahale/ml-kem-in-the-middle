# ML-KEM In The Middle

An extremely dumb way of turning ML-KEM ciphertexts (i.e. encapsulated keys) into pseudo-random
bitstrings.

> [!CAUTION]
> ⚠️ You should not use this. ⚠️
>
> Neither the design nor the implementation of this library have been independently evaluated.
>
> In addition, there is absolutely no guarantee of backwards compatibility.

## The Problem

ML-KEM-768 ciphertexts are a sequence of 1024 field elements of `Z_q`, packed as 10-bit integers
into a 1088-byte array. This produces tell-tale biases in bit frequencies, which allow passive
adversaries to distinguish ML-KEM-768 ciphertexts from random noise.

## The Solution

Instead of encoding the ciphertext packed as 10-bit integers, this expands each field element to 32
bits and adds the field modulus `Q` to each a random number of times, encoding the results as
unsigned 32-bit little endian integers.

Revealing the original ciphertext is just a matter of decoding those integers and reducing them
modulo `Q` to field elements.

## The Results

The hidden ciphertexts produced by this method pass all [dieharder][] tests as of v3.31.1, except
for `rgb_minimum_distance`.

[dieharder]: https://webhome.phy.duke.edu/~rgb/General/dieharder.php

> [!CAUTION]
>
> Unlike ML-KEM-768 ciphertexts, hidden ciphertexts are malleable. Active adversaries can change
> them without changing the decapsulated key. Govern yourself accordingly.

## License

Copyright © 2024 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
