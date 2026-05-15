import { randomBytes } from "@noble/ciphers/utils.js";
import { xchacha20poly1305  } from '@noble/ciphers/chacha.js';
import stringify  from 'fast-json-stable-stringify';


interface UserInfo {
  username: string;
  publicKey: CryptoKey;
}

export interface CipherObject{
  data : Uint8Array;
  filename: string;
  file_type: string;
  recipients: UserInfo[];
}

interface SymmetricMetadata {
  cipher: string;
  key_size_bits: number;
  nonce_size_bytes: number;
  tag_size_bytes: number;
}

interface AsymmetricMetadata {
  cipher: string;
  key_size_bits: number;
  public_exponent: number;
  hash: string;
  mgf: string;
}

interface KeyWrap{
  username: string,
  wrappedKey: string
}

interface EncryptionMetadata {
  file_type: string;
  filename: string;
  timestamp: string;
  encryption: "Hybrid";
  symmetric: SymmetricMetadata;
  asymmetric: AsymmetricMetadata;
  nonce: string;
  recipients: KeyWrap[];
}


export interface Container{
  metaData: EncryptionMetadata;
  cipherText_w_tag: string;
}


/*
  Inspiration for Base64 encoding and decoding functions retrieved from:
  https://developer.chrome.com/blog/how-to-convert-arraybuffer-to-and-from-string
  &
  https://developer.chrome.com/blog/how-to-convert-arraybuffer-to-and-from-string
*/
export function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

export function bytesToB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}


export class KeyManager {


  /*
    Implementation Retrieved from:
    https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
  */
  async generate_key_pair(): Promise<{publicKey: CryptoKey; privateKey: CryptoKey}>{
    const keyPair = await globalThis.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1,0,1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );

    return {publicKey: keyPair.publicKey, privateKey: keyPair.privateKey};
  }

  /*
    Implementation Retrieved from:
    https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey
  */
  async exportPublicKey(publicCryptoKey: CryptoKey): Promise<string>{
    const exported = await globalThis.crypto.subtle.exportKey(
      "spki",
      publicCryptoKey
    );
    const exportedAsBase64 = bytesToB64(new Uint8Array(exported));
    return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
  }

  async exportPrivateKey(privateCryptoKey: CryptoKey): Promise<string>{
    const exported = await globalThis.crypto.subtle.exportKey(
      "pkcs8",
      privateCryptoKey
    );
    const exportedAsBase64 = bytesToB64(new Uint8Array(exported));
    return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
  }

  /*
    Implementation Retrieved from:
    https://github.com/mdn/dom-examples/blob/main/web-crypto/import-key/spki.js
  */
  async importPublicKey(pem: string): Promise<CryptoKey>{
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';

    if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
      throw new Error('La clave no tiene estructura PEM');
    }

    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length).replace(/\s/g, '');

    const binaryDer = b64ToBytes(pemContents);

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "spki",
      binaryDer.buffer as ArrayBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["encrypt"]
    );

    return cryptoKey;
  }

  async importPrivateKey(pem: string): Promise<CryptoKey> {
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';

    if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
      throw new Error('La clave no tiene estructura PEM');
    }

    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length).replace(/\s/g, '');

    const binaryDer = b64ToBytes(pemContents);

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "pkcs8",
      binaryDer.buffer as ArrayBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["decrypt"]
    );

    return cryptoKey;
  }


}

export class HybridEncryption {

  async encrypt_file(cipherObject: CipherObject): Promise<Container> {
    if (cipherObject.recipients.length === 0) {
      throw new Error("No recipients provided for encryption.");
    }

    // Parameters fro Symmetric Encryption
    const key = randomBytes(32);
    const nonce = randomBytes(24);

    const recipientsWrappedKeys: KeyWrap[] = [];

    for (const recipient of cipherObject.recipients){
      const encryptedKeyRecipient = await globalThis.crypto.subtle.encrypt(
        { name : "RSA-OAEP" },
        recipient.publicKey,
        key
      );

      recipientsWrappedKeys.push(
        {
        username: recipient.username,
        wrappedKey: bytesToB64(new Uint8Array(encryptedKeyRecipient))
        }
      );
    }

    const metaData : EncryptionMetadata = {
      file_type: cipherObject.file_type,
      filename: cipherObject.filename,
      timestamp: new Date().toISOString(),
      encryption: "Hybrid",
      symmetric: {
        cipher: "XChacha20-Poly1305",
        key_size_bits: 256,
        nonce_size_bytes: 24,
        tag_size_bytes: 16
      },
      asymmetric: {
        cipher: "RSA-OAEP",
        key_size_bits: 2048,
        public_exponent: 65537,
        hash: "SHA-256",
        mgf: "MGF1-SHA256",
      },
      nonce: btoa(String.fromCharCode(...nonce)),
      recipients: recipientsWrappedKeys,
    };

    const aad = new TextEncoder().encode(stringify(metaData));
    const chacha = xchacha20poly1305(key, nonce, aad);
    const cipherText_w_tag = chacha.encrypt(cipherObject.data);

    const container : Container = {
      metaData,
      cipherText_w_tag: bytesToB64(cipherText_w_tag)
    };

    return container;
  }

  async decrypt_file( container: Container,  recipientUsername: string, recipientPrivateKey: CryptoKey): Promise<Uint8Array> {

    const metaData : EncryptionMetadata = container.metaData;
    const cipherText_w_tag = b64ToBytes(container.cipherText_w_tag);

    const recipientKeyWrap : KeyWrap | undefined = metaData.recipients.find( (r : KeyWrap) => r.username === recipientUsername);
    if (!recipientKeyWrap) throw new Error("Recipient not found in metadata");

    const wrappedKeyBytes = b64ToBytes(recipientKeyWrap.wrappedKey);
    const nonce = b64ToBytes(metaData.nonce);

    const symmetricKeyBuffer = await globalThis.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        recipientPrivateKey,
        wrappedKeyBytes.buffer as ArrayBuffer
    );

    const symmetricKey = new Uint8Array(symmetricKeyBuffer);
    const aad = new TextEncoder().encode(stringify(metaData));

    const chacha = xchacha20poly1305(symmetricKey, nonce, aad);
    return chacha.decrypt(cipherText_w_tag);
  }
}

