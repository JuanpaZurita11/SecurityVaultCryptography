# D4 — Digital Signatures: `SignatureCryptoModule`

Extends the secure vault system with **origin authentication and integrity guarantees** via Ed25519 digital signatures.

---

## Algorithms

| Layer | Algorithm | Details |
|-------|-----------|---------|
| Symmetric encryption | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce, 128-bit AEAD tag |
| Key encapsulation | ECIES-style over X25519 | Ephemeral ECDH + HKDF-SHA256 per recipient |
| Key wrapping | XChaCha20 | Encrypts symmetric key for each recipient |
| Digital signature | Ed25519 | Signs the full container after encryption |
| Signer fingerprint | SHA-256(publicKey) | Used to verify key ownership before signature check |

### Why ECIES-style instead of RSA-OAEP

Previous deliverables used RSA-OAEP to wrap the symmetric key. This forced every user to manage **two separate key pairs**: one RSA pair for encryption and a separate pair (e.g. ECDSA) for signing.

By switching to ECIES-style key encapsulation over X25519, the system can derive the X25519 keys directly from the user's Ed25519 signing key via `toMontgomery()`. Both curves are mathematically equivalent (both based on Curve25519), so **one Ed25519 key pair now serves both purposes**: encryption and signing. This simplifies key management significantly.

```
Ed25519 keypair
  ├─ sign/verify        → ed25519.sign() / ed25519.verify()
  └─ ECDH (encrypt)     → ed25519.utils.toMontgomery(pub)
                           ed25519.utils.toMontgomerySecret(priv)
```

---

## What Is Signed

The signature covers the complete container serialized as JSON:

```
{
  metaData,      ← AAD used in symmetric encryption (file_type, timestamp, cipher params)
  nonce,         ← binds ciphertext to its encryption context
  recipients[],  ← prevents adding/removing recipients after signing
  cipherText,    ← detects any modification to encrypted content
  tag            ← Poly1305 authentication tag
}
```

> **Note:** `metaData` doubles as the AAD for XChaCha20-Poly1305. Signing it at the container level extends that protection to the signature layer.

### Why hash before signing?

Ed25519 applies SHA-512 internally before signing, so no explicit pre-hashing is needed in code. Conceptually, hashing is required to:

1. Compress an arbitrary-length message to a fixed-size digest the signature algorithm can operate on.
2. Ensure any single-bit change in the input produces a completely different digest (avalanche effect).
3. Prevent algebraic attacks possible when signing raw data directly.

---

## Container Schema

```json
{
  "metaData": {
    "file_type": "...",
    "timestamp": "ISO-8601",
    "encryption": "Hybrid",
    "symmetric": { "cipher": "XChacha20-Poly1305", "key_size_bits": 256, "nonce_size_bytes": 24, "tag_size_bytes": 16 },
    "asymmetric": { "scheme": "ECIES-style", "curve": "X25519", "kdf": { "algorithm": "HKDF", "hash": "SHA-256" }, "key_wrapping": { "cipher": "XChaCha20", "nonce_size_bytes": 24 } }
  },
  "nonce": "<base64>",
  "recipients": [
    { "username": "...", "ephimeralPub": "<base64>", "wrapNonce": "<base64>", "wrappedKey": "<base64>" }
  ],
  "cipherText": "<base64 — ciphertext without tag>",
  "tag": "<base64 — last 16 bytes of AEAD output>",
  "signature": "<base64 — ed25519.sign(container)>",
  "signerInfo": {
    "username": "...",
    "fingerprint": "<base64 — SHA-256(publicKey)>"
  }
}
```

---

## Flows

### Encrypt & Sign
```
encrypt_file()
  ├─ generate symmetric_key + nonce
  ├─ for each recipient:
  │    ├─ ephemeral X25519 keygen
  │    ├─ ECDH → HKDF-SHA256 → derivedKey
  │    └─ wrappedKey = XChaCha20(derivedKey, wrapNonce, symmetric_key)
  └─ cipherText = XChaCha20-Poly1305(symmetric_key, nonce, AAD=metaData).encrypt(data)

generate_signature()
  ├─ call encrypt_file()
  ├─ container = { metaData, nonce, recipients, cipherText, tag }
  ├─ signature = ed25519.sign(JSON.stringify(container), privKey)
  └─ return { ...container, signature, signerInfo: { username, fingerprint } }
```

### Verify & Decrypt
```
validate_signature(container, senderPublicKey)
  ├─ assert SHA-256(senderPublicKey) == container.signerInfo.fingerprint
  ├─ msg = { metaData, nonce, recipients, cipherText, tag }
  ├─ assert ed25519.verify(container.signature, JSON.stringify(msg), senderPublicKey)
  └─ return true  (throws on any failure)

decrypt_file()
  ├─ toMontgomerySecret(privKey) → X25519 private key
  ├─ ECDH with ephimeralPub → HKDF → derivedKey
  ├─ symmetric_key = XChaCha20(derivedKey, wrapNonce, wrappedKey)
  └─ return XChaCha20-Poly1305(symmetric_key, nonce, AAD=metaData).decrypt(cipherText)
```

---

## Security Decisions

### Why sign the ciphertext and not the plaintext?

Signing after encryption (Encrypt-then-Sign) ensures the container —exactly as built by the sender— cannot be tampered with. If an attacker re-encrypted the same plaintext, they would produce a different ciphertext, which would immediately invalidate the signature. Additionally, XChaCha20-Poly1305 already authenticates the plaintext via its AEAD tag; the signature adds a second layer of authentication at the container level.

### What happens if the signature is not verified first?

Skipping verification before decryption opens several attack vectors: an attacker could submit a crafted container and observe error behavior to extract information (decryption oracle), or claim false ownership of a validly-encrypted container. The system is designed to **fail fast** — `validate_signature` must be called before `decrypt_file` and will throw immediately on any failure.

### What happens if metadata is excluded from the signature?

The metadata contains all security-relevant parameters (cipher suite, recipient list, nonce). Excluding it allows an attacker to:

- Swap the recipient list to add their own key and gain decryption access.
- Modify algorithm fields to downgrade cipher parameters.
- Replay old containers by changing the timestamp without invalidating the signature.

Since `metaData` is already the AAD for the symmetric encryption, signing it at the container level naturally extends this protection.

---

## Required Tests

| # | Test case | Expected result |
|---|-----------|-----------------|
| 1 | Valid signature | `validate_signature` returns `true`; `decrypt_file` returns original plaintext |
| 2 | Modified `cipherText` | `ed25519.verify` fails → `Error: Signature verification failed` |
| 3 | Modified `metaData` | `ed25519.verify` fails → `Error: Signature verification failed` |
| 4 | Wrong public key | Fingerprint mismatch → `Error: Fingerprint mismatch` |
| 5 | Signature removed | Invalid signature bytes → `Error` thrown |

---

## Dependencies

| Package | Usage |
|---------|-------|
| `@noble/curves` | Ed25519 (sign/verify), X25519 (ECDH) |
| `@noble/hashes` | SHA-256, HKDF |
| `@noble/ciphers` | XChaCha20-Poly1305, XChaCha20 |