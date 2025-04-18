# ECB Attacks

## ECB vs CBC

### Introduction

This exercise demonstrates the difference between ECB (Electronic Codebook) and CBC (Cipher Block Chaining) encryption modes. The server randomly selects one of these modes to encrypt a plaintext message provided by the client. The client then analyzes the ciphertext to determine which mode was used.

### How to Perform the Test

1. **Start the Server**:
   - Run the `server.py` script to start the encryption server.
   - The server listens for incoming connections and encrypts messages in either ECB or CBC mode.

2. **Run the Client**:
   - Execute the `client.py` script to connect to the server.
   - The client sends a specially crafted plaintext message to the server.

3. **Analyze the Ciphertext**:
   - The client receives the ciphertext and splits it into blocks.
   - If two consecutive blocks are identical, the encryption mode is ECB.
   - Otherwise, the encryption mode is CBC.

4. **Output**:
   - The client prints the detected encryption mode (ECB or CBC) based on the ciphertext analysis.

### Key Observations

- **ECB Mode**:
  - Identical plaintext blocks produce identical ciphertext blocks.
  - This makes ECB mode vulnerable to pattern recognition attacks.

- **CBC Mode**:
  - Each ciphertext block depends on the previous block, introducing randomness.
  - This makes CBC mode more secure against pattern recognition.

### Example Output

```
Sending: b'AAAAAAAAAAAAAAAAAAAAAAAA'
<hexadecimal ciphertext>
Selected mode is ECB
```

## ECB Copy & Paste Attack

### Introduction

This exercise demonstrates a vulnerability in the ECB (Electronic Codebook) encryption mode. By exploiting the deterministic nature of ECB, an attacker can manipulate ciphertext blocks to forge an admin cookie.

### How to Perform the Test

1. **Start the Cookie Generation Server**:
   - Run the `copypaste_server_gencookie_service.py` script to start the server that generates encrypted cookies.

2. **Start the Test Cookie Service**:
   - Run the `copypaste_testcookie_service.py` script to start the server that validates cookies.

3. **Run the Attack Script**:
   - Execute the `copypaste_attack.py` script to perform the attack.
   - The script:
     - Sends a crafted email to the cookie generation server.
     - Extracts ciphertext blocks corresponding to the "admin" role.
     - Combines these blocks with valid user blocks to forge an admin cookie.

4. **Send the Forged Cookie**:
   - The forged cookie is sent to the test cookie service.
   - If successful, the server recognizes the attacker as an admin.

### Key Observations

- **ECB Mode Vulnerability**:
  - ECB encrypts identical plaintext blocks into identical ciphertext blocks.
  - This allows attackers to manipulate ciphertext by rearranging blocks.

- **Attack Steps**:
  - Craft a plaintext block containing "admin" padded to the block size.
  - Use the server to encrypt this block.
  - Replace the "role=user" block in a valid cookie with the "admin" block.

### Example Output

```
Cookie: email=aaaaaaa@b.com&UID=10&role=user
Forged Cookie: email=aaaaaaa@b.com&UID=10&role=admin
You are an admin!
```

## ECB ACP (Adaptive Chosen Plaintext) Attack

### Introduction

This exercise demonstrates an Adaptive Chosen Plaintext (ACP) attack on AES encryption in ECB mode. The attacker exploits the deterministic nature of ECB to discover a secret appended to a plaintext message. By carefully crafting inputs and analyzing ciphertext blocks, the attacker can recover the secret without brute-forcing the entire search space.

### How to Perform the Test

1. **Start the Server**:
   - Run the `ACP_attack_server.py` script to start the encryption oracle.
   - The server listens for incoming connections and encrypts messages using AES in ECB mode.

2. **Run the Attack Script**:
   - Execute the `ACP_attack_client.py` script to perform the attack.
   - The script:
     - Sends crafted plaintext messages to the server.
     - Analyzes the ciphertext to discover the secret one character at a time.

3. **Output**:
   - The client prints the discovered secret after completing the attack.

### Key Observations

- **ECB Mode Vulnerability**:
  - Identical plaintext blocks produce identical ciphertext blocks.
  - This allows attackers to infer information about the plaintext by analyzing ciphertext patterns.

- **Attack Steps**:
  - Align the secret at the end of a block using padding.
  - Guess each character of the secret by comparing ciphertext blocks.
  - Repeat until the entire secret is discovered.

### Example Output

```
Sending:  - and the sec:A
Found new character = A
Sending:  - and the sec:AB
Found new character = B
...
Secret discovered = ABCDEFGHIJKLMNOP
```
