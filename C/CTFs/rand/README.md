## Rand CTF

### "Bytewise Operations" CTF

#### Challenge Description
In this challenge, you need to perform bytewise operations on two randomly generated strings. The operations include:
1. Generating two random strings (`rand1` and `rand2`).
2. Performing the bytewise OR of `rand1` and `rand2` to obtain `k1`.
3. Performing the bytewise AND of `rand1` and `rand2` to obtain `k2`.
4. Performing the bytewise XOR of `k1` and `k2` to obtain the final key.

The flag is the result (key) when the randomly generated strings are:
- `rand1 = ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08`
- `rand2 = 4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2`

#### Key Instructions
1. Initialize the two random strings `rand1` and `rand2` with the given values.
2. Perform the bytewise OR operation on `rand1` and `rand2` to get `k1`.
3. Perform the bytewise AND operation on `rand1` and `rand2` to get `k2`.
4. Perform the bytewise XOR operation on `k1` and `k2` to get the final key.
5. Print the key in the required format surrounded by `CRYPTO25{}`.

#### Example Code
Refer to the [rand.c](./Bytewise-operations/rand.c) file for the implementation details.

#### Additional Resources
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [C Programming Language](https://en.wikipedia.org/wiki/C_(programming_language))
