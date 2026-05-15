# Encryption Design

## Goals

- Authenticated Encryption with Associated Data (AEAD)
  - Confidentiality
  - Integrity
  - Tamper detection

## Introduction

### **AES**

In 2000, NIST announced the selection of the Rijndael block cipher family as the winner of the Advanced Encryption Standard (AES) competition. Three members of the Rijndael familiy are specified in the FIPS 197 Standard: AES-128, AES-192, and AES-256. Each of them transforms data in blocks of 128 bits, and the numerical suffix indicates the bit length of the associated cryptographic keys.

### **Galois/Counter Mode (GCM)**

- Is a mode of operation of the AES algorithm

The two functions that comprise GCM are called authenticated encryption and authenticated decryption. The authenticated encryption function encrypts the confidential data and computes an authentication tag on both the confidential data and any additional, non-confidential data. The authenticated decryption function decrypts the confidential data, contingent on the verification of the tag.

|            | Authenticated Encryption                                        | Autenticated Decryption                                                             |
| ---------- | --------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **Input**  | Initialization Vector, Plaintext, Additional Authenticated Data | Initialization Vector, CipherText, Additional Authenticated Data, Authenticated TAG |
| **Output** | Ciphertext, Authenticated TAG                                   | Plaintext or indication of inauthenticity FAIL                                      |

## Algorithm Requirments

### Key

- **Size**: AES-256 supports the largest bit size and is a widely used encryption technology because it is virtually impenetrable to brute-force attacks.
- **Key generation**: Using the output of a Random Bit Generator.

### NONCE Strategy

> Nonce: Number, string or word used only once for a specific purpose.

GCM requires as input an initialization vector, that can have any number of bits between 1 and 2⁶⁴. The primary purpose of the IV is to be a nonce, that is, to be distinct for each invocation of the encryption operation for a fixed key. It is acceptable for the IV to be generated randomly, as long as the distinctness of the IV values is highly likely. **96-bit IV values can be processed more efficently, so that length is recommended for situations in which efficiency is critical.**

> **Radom Bit Generation** - based Construction

Is the concatation of two fields, called the random field (at least 96 bits) and the free field (may be empty).

## Metadata

- Additional Authenticated Data:
  - Algorithm Version (AES-GCM with 256 key)
  - Creation timestamp
  - File Name
- Nonce
- Authentication TAG

# Security Decisions

## Why AEAD instead of encryption + hash?

GCM provides stronger authentication assurance than a (non-cryptographic) checksum or error detection code; in particular, GCM can detect both 1) accidental modifications of the data and 2) itentional, unathorized modifications.

## What happens if nonce repeats?

If the **Initialization Vectors** are ever repeated for the GCM authenticated encryption function for a given key, then it is likely that an adversary will be able to determine the hash subkey from the resulting ciphertexts. The adversary then could easily construct a ciphertext forgery.

- The adversary could subsittue any ciphertext and AAD strings and use the subkey to generate the valid subsitute TAG. Thus, the authentication assurance essentially is lost.

## What attacker are you defending against?

The design of this Secure Digital Document Vault assumes an Active Adversary. While traditional encryption alone only protects against passive attackers (eavesdroppers trying to read the data), our implementation is built to defend against attackers who have full access to intercept, modify, or tamper with the encrypted file and its metadata.

- Eavesdroppers: We prevent unauthorized reading of the file's contents by using a modern symmetric block cipher (e.g., AES-256).

- Tamperers: We prevent undetected modifications to the ciphertext or unencrypted metadata (AAD) by relying on the AEAD Authentication Tag, which forces decryption to fail safely if tampered with.

# Implementation

The cryptographic core of this module is implemented using the **Pyhton** `criptography` library. For further details, please refer to the official documentation at:
[Authenticated encryption](cryptography.io/en/latest/hazmat/primitives/aead/)
