# SecurityVaultCryptography

**Secure system** for digital documents

## 1. System Overview

### What does it solve?

Traditional storage solutions often suffer from "single point of failure" vulnerabilities, where compromising a single account or device grants access to all sensitve data.

This **vault** addresses the risk of data breaches by ensuring that even if an attacker successfully comprimeses the document storage, the documents remain useless without the keys. Conversely, stealing a private key provides no value without access to the specific encrypted documents.

### What are the core features?

- Encryption of documents
- Authenticity and Integrity verification of documents
- Management and Storage of keys
- Secure Sharing

### What is out of scope

- Insecure Network Infrastructure
- Operating System Corruption

## 2. Architecture Diagram

graph LR
subgraph User_Device [User Device - TRUSTED]
User((User))
App[Application/Vault]
KStore[(Key Store: Private Keys)]

        subgraph Crypto_Ops [Secure Processing]
            Enc[Encryption Engine]
            Sign[Signing Engine]
        end
    end

    subgraph Server_Storage [Storage/Server - UNTRUSTED]
        PubKeys[(Public Keys / Recipients)]
        VaultDB[(Encrypted File Containers)]
    end

    %% Data Flows
    User -->|1. Passphrase| App
    App -->|2. Get Private Key| KStore
    User -->|3. Input Document| Enc
    Enc -->|4. Encrypts| Sign
    Sign -->|5. Signs| App
    App -->|6. Upload Ciphertext + Sig| VaultDB
    PubKeys -->|7. Identify Recipients| App

    %% Styling
    classDef trusted fill:#d4edda,stroke:#28a745,stroke-width:2px;
    classDef untrusted fill:#f8d7da,stroke:#dc3545,stroke-width:2px;
    class User_Device trusted;
    class Server_Storage untrusted;

## 3. Securirty Requeriments

- **Integrity and Anti-Tampering**: The system must ensure that any modification, even a single bit, to a encrypted document or its associated metadata is detected before decryption, preventing the processing of tampered or corrupted files.
- Only
- **Authenticity**: Every document must be cryptographically linked to its owner's identity, allowing verification when shared.
- **Confidentiality**: The system must enforce that decryption is technically impossible for any entity not explicity authorized.
  - An attacker who obtains the encrypted document cannot derive any information without the specific private key.
  - An attacker who compromises a private key cannot access sensitive data unless they also gain unauthorized access to the specific encrypted document associated with it.
- **Private Key Protection**: Private key must be stored in an encrypted state (at rest) and must only be accesible after succesful usre authentication, ensuring that physical access to the device does not grant acces to the keys.

## 4. Threat Model

### Assets

- Digital Documents stored in the vault
- Cryptographic Keys (Public and Private)
- User Authentication Information

### Adversaries

- External attacker with access to the storaged media
  - Can copy data
  - Cannot understand the stored data (is encrypted)

## 5. Trust Assumption

- Users are responsible for the protection and management of their own system credentials.

## 6. Attack Surface

## 7. Design Constraints Derived from Requirements

| Requirement  | Design Constraint                 |
| ------------ | --------------------------------- |
| Intregity    | Must use **Hash**                 |
| Authenticity | Must implement digital signatures |
