# D2  Secure Symmetric Encryption Module

## Module Description

1. **Programming Language**: TypeScript
    - **JS dependencies**:
  ```json
  "dependencies": {
    "@noble/ciphers": "^2.2.0",
    "fast-json-stable-stringify": "^2.1.0",
    "zod": "^4.4.3"
  }
  ```
2. **Execution environment**: Web page FrontEnd

## Goal

Authenticated Encryption with Associated Data (AEAD)
+ **Confidentiality**
+ **Integrity**
+ **Tamper detection**

## Test Environment

This module uses **Vitest** for testing. Follow these steps to set up the environment and try the module yourself on your machine:

1. **Prerequisites**: You must have install Node.js and npm

2. **Environmente Setup**: Download the contents of this module (source code and configuration files). Once inside the module's root directory, install the required dependencies:


```bash
npm install
```

3. **Execute the Tests**: The test are define inside the ./test folder. To launche the test suite, run the following commands in your terminal:

```bash
npm test
```
### Tests executed:

+ Encrypt and decrypt returns identical file
+ Wrong key fails
+ Modified ciphertext fails
+ Modified metadata fails
+ Multiple encryptions produce differente ciphertexts

# Introduction

## ChaCha20

ChaCha20 is a high-speed, lightweight, and highly secure 256-bit symmetric-key cipher used to encrypt and decrypt data. It was designed by Daniel J. Bernstein as an improvement on an earlier cipher called Salsa20. The goal was to create something that is both efficient and secure, especially in software.

AES often benefits from hardware acceleration on modern processors, which makes it extremely fast in those environments. ChaCha20, on the other hand, is designed to perform consistently well even without specialized hardware support, making it a strong choice for mobile devices and low‑power systems.

## Poly1305

Poly1305 is a high-speed Message Authentication Code (MAC) designed by Daniel J. Bernstein (djb). Its primary purpose is to ensure the integrity and authenticity of a message, allowing a receiver to verify that a message has not been tampered with and truly originated from the expected sender.

In modern cryptography, it is almost always paired with the ChaCha20 stream cipher to create an Authenticated Encryption with Associated Data (AEAD) construction, commonly referred to as ChaCha20-Poly1305.

## Implementation

We utilized the @noble/cryptography JavaScript library to implement the XChaCha20-Poly1305 encryption algorithm. The primary distinction between ChaCha20 and XChaCha20 lies in their nonce sizes: while the former uses a 96-bit nonce, the latter extends it to 192 bits, significantly reducing the risk of nonce reuse.

# Algorithm Requirements

## Key

+ **Size**: 256 bits.
+ **Key generation**: Using the output of a Random Bit Generator

## Nonce

> Nonces: Numbre, string or word used only once for a specific purpose.

XChaCha20 requires a 192-bit (24-byte) nonce. This extended length is specifically designed to make the probability of a collision (generating the same nonce twice) negligible.

The most secure and recommended strategy is to generate the full 192 bits randomly using a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).


## Container

```json
{
  "metaData": {
    "file_type": MIME TYPES,
    "filename": string,
    "timestamp": ISO 8601 string,
    "encryption": "Symmetric",
    "parameters":{
      "cipher": "XChacha20+Poly1305",
      "key_size_bits": 256,
      "nonce_size_bytes": 24,
      "tag_size_bytes": 16
    },
    "nonce": Base64 string,
  },
  "cipherText_w_tag": Base64 string
}
```

## Security Decisions

### Why AEAD instead of encryption + hash?

GCM provides stronger authentication assurance than a (non-cryptographic) checksum or error detection code; in particular, GCM can detect both (1) accidental modifications of the data and (2) itentional, unathorized modifications.

### What happends if nonce repeats?

>In practice, nonce reuse can completely compromise confidentiality and may comprosie integrity as well.

If the same nonce is accidentally reused:
+ The underlyin stream cihper (XChaCha20) will generate the same keystream.
+ An attacker can XOR two ciphertext together to recover information about the original plaintexts.
+ Authentication guarantees from Poly1305 can also be weakened, potentially enabling forgery attacks.

Fortunately, **XChaCha20** reduces the risk of accidental nonce collisions by using a 192 bit nonce, making random nonce generation safe for mos applications.

### What attacker are you defending against?

The design of this Secure Digital Document Vault assumes an Active Adversary. While traditional encryption alone only protects against passive attackers (eavesdroppers trying to read the data), our implementation is built to defend against attackers who have full access to intercept, modify, or tamper with the encrypted file and its metadata.

+ Eavesdroppers: We prevent unauthorized reading of the file's contents by using a modern symmetric block cipher (e.g., AES-256).

+ Tamperers: We prevent undetected modifications to the ciphertext or unencrypted metadata (AAD) by relying on the AEAD Authentication Tag, which forces decryption to fail safely if tampered with.
