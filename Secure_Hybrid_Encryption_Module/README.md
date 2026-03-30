# SecurityVaultCryptography

A secure digital document vault that allows users to encrypt files and share them safely with multiple recipients. Only authorized users can decrypt the content, even if the encrypted container is publicly exposed.

---

## Project Structure

The repository is organized into two independent modules, each with its own tests.

**Secure_Symmetric_Encryption_Module** contains the foundational symmetric encryption layer built in D2. It handles file encryption and decryption using AES-256-GCM and includes tests for correct encryption and decryption, multiple encryptions producing different outputs, and rejection of tampered content or wrong keys.

**Secure_Hybrid_Encryption_Module** contains the multi-recipient sharing layer built in D3. It adds RSA key pair management and hybrid encryption on top of D2, and includes tests for all required security scenarios.

---

## D2 — Symmetric Encryption

The symmetric module provides authenticated encryption for files of any size. It uses AES-256-GCM, which both encrypts and authenticates data in a single operation. This means the system does not just hide the content — it also guarantees that nobody has modified it.

Every encryption uses a fresh random nonce of 96 bits generated with a cryptographically secure source. File metadata such as the original filename, timestamp, and algorithm parameters are included as Additional Authenticated Data (AAD). This means the metadata is authenticated by AES-GCM even though it is not encrypted — any change to it will cause decryption to fail.

---

## D3 — Hybrid Encryption and Multi-Recipient Sharing

### Why hybrid encryption is used

Public key algorithms like RSA are not designed to encrypt large amounts of data. They are slow and have strict size limits. AES-256-GCM, on the other hand, is fast and handles files of any size efficiently. Hybrid encryption combines both: AES encrypts the file, and RSA encrypts only the small symmetric key. This gives the speed of symmetric encryption together with the key distribution power of public key cryptography.

### Why symmetric encryption is still needed

The file is encrypted exactly once with a single AES key called the file key. This key is what gets shared with recipients, not the file itself. If we encrypted the file separately for each recipient using RSA, we would produce multiple inconsistent ciphertexts and the process would be impractical for any file larger than a few hundred bytes. Symmetric encryption remains essential for the actual file content.

### Why per-recipient key encryption is required

Each recipient has their own RSA key pair. The file key must be delivered to each person in a form that only they can unwrap. Encrypting the file key with Alice's public key means only Alice's private key can recover it. This allows each recipient to be fully independent — Alice cannot use her credentials to access what was encrypted for Bob, and vice versa.

---

## Security Decisions

### How do recipients identify their key?

Each recipient entry in the container stores a user identifier and a key fingerprint. The fingerprint is a SHA-256 hash computed over the public key of the recipient. This is a deterministic and unique identifier — the same key always produces the same fingerprint regardless of when or where it is computed.

When decrypting, the system first finds the entry matching the provided user ID, then computes the fingerprint of the private key being used and compares it against the stored fingerprint. If they do not match, decryption is rejected immediately. This prevents identity confusion attacks where someone claims to be a recipient without having the correct key.

### What happens if an attacker modifies the recipient list?

The recipient list is embedded in the container metadata, which is used as AAD in AES-256-GCM. Because AES-GCM authenticates both the ciphertext and the AAD together, any modification to the metadata — adding a new recipient, removing one, or changing an identifier — causes the authentication tag to fail. Decryption raises an error and the file cannot be accessed. This makes the recipient list cryptographically tamper-evident.

### What happens if the wrong public key is used?

The system applies three independent checks. First, the fingerprint of the provided private key is compared against the one stored in the container — if they differ, an error is raised immediately. Second, if that check were bypassed, RSA-OAEP decryption with the wrong key would fail on its own. Third, even if both previous checks were bypassed, AES-GCM would reject decryption because the recovered key would be garbage and the authentication tag would not verify. This layered approach ensures that no single bypass can compromise the system.

---

## Tests

### D3 — Hybrid Encryption Tests

**test_dos_destinatarios** verifies that both Alice and Bob, when included as recipients, can independently decrypt the same encrypted file using their own private keys.

**test_usuario_no_autorizado** verifies that a user whose ID is not in the recipient list cannot decrypt the file and receives a clear error.

**test_lista_destinatarios_alterada** verifies that modifying the recipient list in the container metadata causes an authentication failure during decryption, preventing recipient list manipulation.

**test_llave_privada_incorrecta** verifies that using a private key whose fingerprint does not match the stored one raises an error before any decryption is attempted.

**test_eliminar_destinatario** verifies that removing a recipient's entry from the container denies their access, and that also modifying the metadata breaks access for remaining recipients.

---
