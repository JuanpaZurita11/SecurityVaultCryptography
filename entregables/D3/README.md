# D3 - Hybrid Encryption (Secure File Sharing)

## This adds to and builds upon the features provided by D3

## Module Description

1. **Programming Language**: TypeScript
    - **JS dependencies**:
  ```json
  "dependencies": {
    "@noble/ciphers": "^2.2.0",
    "fast-json-stable-stringify": "^2.1.0"
  }
  ```
2. **Execution environment**: Web page FrontEnd

## Goal

Extend your system to support secure file sharing between multiple users using hybrid encryption.

The system must allow:
+ A file encrypted once.
+ Multiple authorized recipients.
+ Only those recipients can decrypt.

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

+ If a file is shared with 2 users, both can decrypt it
+ Unauthorized user cannot decrypt
+ If the recipient list is tampered, the decryption fails
+ Wrong private key, process fails
+ Removing a recipient entry, it will break access.

# Hybrid Design Explanation

### Why is hybrid encryption used ?

Implementing a hybrid scheme is the optimal solution for balancing key distribution security with high-volume data processing efficiency. Pure alternatives present critical limitations:

+ **Symmetric Encryption Inefficiency (The Distribution Problem)**: While symmetric encryption is extremely fast, sharing the same key with multiple recipients violates the principle of non-repudiation and exponentially increases risk: if one key is compromised, the confidentiality of all messages for all users is lost.
+ **Asymmetric Encryption Computational Cost (The Performance Problem)**: Asymmetric algorithms are orders of magnitude slower than symmetric ones. Encrypting a 1 GB file ten times would not only saturate server storage (10 GB total) but would also consume unnecessary CPU cycles, creating unacceptable latency for the user.

Hybrid encryption combines the best of both worlds through the following workflow:

+ **Performance**: A symmetric key is generated to encrypt the 1 GB file only once, ensuring optimal processing speed.
+ **Distribution Security**: Instead of encrypting the entire file for each recipient, only the small symmetric key is encrypted using each recipient's public key.
+ **Efficient Resource and Storage Usage**: Sharing information with multiple people should not imply duplicating server space consumption. The most efficient logic consists of processing the payload once and appending only the necessary data fragments so that each recipient can unlock it. In this way, we move from managing multiple heavy containers to a single intelligent container with personalized access.


### Why is symmetric encryption stilll needed?

+ **Performance**: Asymmetric encryption algorithms are computationally expensive and are not designed to encrypt large volumes of data.
+ **Multi-user Scalability**: The file is encrypted only once with the symmetric key. Subsequently, that same key is encrypted for each recipient. There is no need to create a separate secure container for every file and its authorized users.
+ **AEAD (Authenticated Encryption with Associated Data)**: Since only one "container" is involved, it is easy to verify any tampering attempts, both to the target ciphertext and its associated metadata.


### Why is per-recipient encryption requiered?

Encryption is performed per recipient—using their public key—to enable the efficient and secure distribution of the container. Each authorized user will have their own unique key wrap.

## Security Decisions

### How do recipients identify their key?


#### KeyWrap Structure
```json
{
  "username": string,
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
    "encryption": "Hybrid",
    "symmetric": {
      "cipher": "XChacha20-Poly1305",
      "key_size_bits": 256,
      "nonce_size_bytes" : 24,
      "tag_size_bytes": 16
    }
    "asymmetric":{
      "cipher": "RSA-OAEP",
      "key_size_bits": 2048,
      "public_exponent": 65537,
      "hash": "SHA-256",
      "mgf": "MGFI-SHA256"
    }
    "nonce": Base64 string,
    "recipients": KeyWrap[]
  }
  "cipherText_w_tag": Base64 string
}
```
Each authorized recipient locates their wrapped symmetric key within the KeyWrap-type array located in the container's metadata. Since identification is performed using the recipient ID, it is a strict application-side requirement that this identifier be unique and deterministic for each user.

### What happens if an attacker modifies the recipient list?

The recipient list is integrated into the container's metadata, which is used as Additional Authenticated Data (AAD) within the XChacha20-Poly1305 symmetric encryption algorithm. The algorithm generates an authentication tag that inextricably binds the encrypted content to its AAD. If an attacker attempts to modify a recipient identifier or alter the list to escalate privileges, the authentication tag will fail during the decryption process. This ensures that no one can change who has access to the container without the system detecting the intrusion and halting decryption.

### Whaqt happens if the public key is wrong?

To access the content, the recipient must locate their specific entry in the metadata list and use their private key to reverse the wrapping process (unwrapping) via the RSA-OAEP algorithm. If decryption is attempted using a key that does not correspond to the public key originally used, the decryption algorithm will fail. This will prevent the retrieval of the symmetric key and, consequently, deny access to the container's content.

