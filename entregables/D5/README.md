# D5 — Digital Signatures & Authentication

## This adds to and builds upon the features provided by D3

## Module Description

1. **Programming Language**: TypeScript
    - **JS dependencies**:
  ```json
  "dependencies": {
    "@noble/ciphers": "^2.2.0",
    "@noble/curves": "^2.2.0",
    "@noble/hashes": "^2.2.0",
    "fast-json-stable-stringify": "^2.1.0"
  }
  ```
2. **Execution environment**: Web page FrontEnd

## Goal

A recipient must be able to verify that a file was created by a specific user and has not been modified since it was signed.

# Test Environment

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

+ Valid signature -> file accepted
+ Modified ciphertext -> rejected
+ Modified metadata -> rejected
+ Wrong public key -> rejected
+ Signature removed -> rejected


## Updates (Last version in ../D3)

We continue with the hybrid encryption scheme with some changes:

### Symmetric Algorithm

Previously, RSA-OAEP was used to encrypt the symmetric key for each recipient — an algorithm useful for asymmetric encryption but one that does not support digital signatures. Consequently, the system migrated to Ed25519, a digital signature scheme based on Curve25519. In addition to ensuring authenticity, it offers practical advantages over RSA: significantly smaller keys (32 bytes compared to the typical 256–512 bytes of RSA), faster operations, and an equivalent or superior level of security.

Additionally, Ed25519 keys can be mathematically transformed into the Curve25519 Montgomery representation, allowing their use with X25519 for key agreement. Based on this mechanism, an ECIES-type scheme is implemented to encapsulate the symmetric key individually for each recipient, combining an ephemeral ECDH exchange, key derivation via HKDF, and authenticated encryption; this guarantees both confidentiality and integrity within the envelope.

### Container Structure

Implementation updates also required modifications to the container metadata. Since JSON does not guarantee key ordering, any shift in the sequence—even if the data remains identical—results in a different hash. This discrepancy would ultimately compromise the container's integrity verification.

#### KeyWrap Structure

```json
{
  "username": string,
  "wrapNonce": Base64 string,
  "wrappedKey": Base64 string
}
```

#### Container Canonic Structure

```json
{
  "metaData": {
    "file_type": MIME TYPES,
    "filename": string,
    "timestamp": ISO 8601 string,
    "owner_fingerprint": Base64 string,
    "encryption": {
      "cipher": "XChacha20-Poly1305",
      "key_size_bits": "256",
      "nonce_size_bits": "192",
      "tag_size_bits": "128"
    },
    "keyWrapping": {
      "scheme": "ECIES-STYLE",
      "asymmetric": {
        "curve": "X255519",
        "kdf": {
          "alg": "HKDF",
          "hash": "SHA-256"
        }
      },
      "symmetric": {
        "cipher": "XChaCha20",
        "key_size_bits": 256
      }
    },
    "container_key": Base64 string,
    "recipients": KeyWrap[],
    "nonce": Base64 string
  },
  "cipherText_w_tag": Base64 string,
  "signature_alg": "Ed25519",
  "signer_id": string,
  "signature": Base64 string
}
```

A 'Canonical Form' is defined for the container and enforced during object instantiation. Furthermore, the fast-json-stable-stringify library is used for serialization prior to signing; this ensures deterministic ordering and consistent hash stability.

## Ownership, authenticity, integrity, and distribution of the container

Previously, metadata integrity—including the recipient list—was guaranteed by including it as AAD (Additional Authenticated Data) within the XChaCha20-Poly1305 scheme. While functional, this enforced container immutability: any change to the recipients required a full re-encryption of the data.

By implementing digital signatures, we shifted the recipient list validation to the asymmetric layer, allowing for dynamic modifications. To prevent impersonation attacks (where a third party modifies the list and re-signs the container with their own key), we established a cryptographic link between both layers:

- **Identity Anchor in AAD:** The creator's public key fingerprint is embedded within the symmetric encryption's AAD. Since AAD cannot be altered without the encryption key, it serves as a protected statement of ownership.
- **Cross-Validation:** During verification, the system ensures that the public key used to validate the signature matches the fingerprint stored in the AAD exactly.

Consequently, even if an attacker re-signs the container, they cannot alter the original fingerprint in the AAD. Any impersonation attempt is detected immediately due to the discrepancy between the signer's identity and the creator's identity.

In this implementation, the AAD used during symmetric encryption includes all metadata content except for the recipients and nonce fields.

## Summary

### Why Ed25519?

Ed25519 was selected as the digital signature scheme due to the following technical advantages:

- **Modern Security:** It offers a 128-bit security level using state-of-the-art elliptic curves, providing resistance against side-channel and collision attacks.
- **Deterministic Signatures:** Unlike ECDSA, it does not rely on a random number generator (RNG) to create signatures. This eliminates critical vulnerabilities caused by system entropy failures.
- **High Performance:** It is significantly faster in signing and verification operations than alternatives like RSA or ECDSA, optimizing CPU overhead.
- **Space Efficiency:** It generates compact 64-byte signatures and 32-byte public keys, minimizing the size growth of the JSON container.
- **Resilience:** Specifically designed to prevent error-prone implementations, ensuring consistent integrity and authenticity.

### What data is signed

An object is constructed following the container's canonical structure, omitting only the signature property. This object is then serialized—using the fast-json-stable-stringify library—and signed. This approach ensures the total integrity of the container. Furthermore, including fields such as signer_id and signature_alg within the signed payload enhances security by inextricably linking the signer's identity and the specific algorithm used to the data itself.

## Security Decisions

### Why sign the ciphertext and not the plaintext?

The plaintext does not travel in the container at all, it is encrypted and replaced by the ciphertext. But more importantly, signing the plaintext would create a vulnerability: an attacker could take a legitimate signed plaintext, re-encrypt it with a different key or for different recipients, and the original signature would still appear valid over the plain content. Signing the ciphertext ties the signature to this specific encryption, with this specific key, for these specific recipients.

### Why must verification happen before decryption?

If decryption runs first, the system is already trusting the container before checking whether it came from the right person. An attacker could craft a malicious container that causes errors during decryption, potentially leaking information through error messages or timing. Verifying first means the container is authenticated before any cryptographic operations run on it.

### How signers are identified

Signer identification is handled through a three-tier verification process that bridges the gap between application logic and cryptographic security:

1. **Application Layer (signer_id):** Each container includes a signer_id field. This serves as a high-level identifier (e.g., a UUID or alias) that allows the application to quickly recognize who is claiming to be the author and to fetch their corresponding public key from a database or keychain.
2. **Signature Layer (Public Key):** Once the signer_id is recognized, the system uses the associated Public Key to verify the digital signature. This confirms that the container's content has not been tampered with and that the signer possesses the private key linked to that identity.
3. **Cryptographic Anchor (AAD Fingerprint):** To prevent "identity substitution" (where an attacker swaps the original signer_id and signature for their own), we use a security anchor. The fingerprint of the creator's public key is stored as Authenticated Additional Data (AAD) within the XChaCha20-Poly1305 encryption.

#### Validation Logic:

The system performs a mandatory cross-check:

Fingerprint(Signer's Public Key) = Fingerprint stored in AAD

If a third party modifies the signer_id and re-signs the container, the fingerprints will not match. Since the AAD is protected by the symmetric encryption key, the attacker cannot update the fingerprint, making the deception detectable.