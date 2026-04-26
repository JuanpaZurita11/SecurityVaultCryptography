import { CipherObject, EncryptionMetadata } from "./types";
import { randomBytes } from "@noble/ciphers/utils.js";
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

export class KeyManager {

  /*
    https://developer.chrome.com/blog/how-to-convert-arraybuffer-to-and-from-string
  */
  private ab2str(buf : ArrayBuffer): string{
    return String.fromCharCode(...new Uint8Array(buf));
  }

  /*
    Implementation Retrieved from:
    https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey
  */
  async exportPublicCryptoKey(publicCryptoKey: CryptoKey): Promise<string>{
    const exported = await globalThis.crypto.subtle.exportKey(
      "spki",
      publicCryptoKey
    );
    const exportedAsString = this.ab2str(exported);
    const exportedASBase64 = globalThis.btoa(exportedAsString);
    return exportedASBase64;
  }

  async exportPrivateCryptoKey(privateCryptoKey: CryptoKey): Promise<string>{
    const exported = await globalThis.crypto.subtle.exportKey(
      "pkcs8",
      privateCryptoKey
    );
    const exportedASString = this.ab2str(exported);
    const exportedASBase64 = globalThis.btoa(exportedASString);
    return exportedASBase64;
  }

  /*
    Implementation Retrieved from:
    https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
  */
  async generate_key_pair(): Promise<{publicKey: string; privateKey: string}>{
    const keyPair = await globalThis.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1,0,1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt",]
    );

    const publicKey = await this.exportPublicCryptoKey(keyPair.publicKey);
    const privateKey = await this.exportPrivateCryptoKey(keyPair.privateKey);

    return {publicKey, privateKey};
  }
}

export class HybridEncryption {

  /*
    https://developer.chrome.com/blog/how-to-convert-arraybuffer-to-and-from-string
  */
  private ab2str(buf : ArrayBuffer): string{
    return String.fromCharCode(...new Uint8Array(buf));
  }

  /*
    https://developer.chrome.com/blog/how-to-convert-arraybuffer-to-and-from-string
  */
  private str2ab(str: string): ArrayBuffer {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++){
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }

  /*
    Implementation Retrieved from:
    https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
  */
  async prepareKeyforEncryption(publicKey:string){
    const binaryDerString = globalThis.atob(publicKey);
    const binaryDer = this.str2ab(binaryDerString);

    return await globalThis.crypto.subtle.importKey(
      "spki",
      binaryDer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    );
  }

  async encrypt_file(cipherObject: CipherObject){

    // Parameters fro Symmetric Encryption
    const key = randomBytes(32);
    const nonce = randomBytes(24);

    /*

    const ownerCryptoKey = await this.prepareKeyforEncryption(cipherObject.ownerKey);
    const encryptedKeyOwner = await globalThis.crypto.subtle.encrypt(
      { name : "RSA-OAEP" },
      ownerCryptoKey,
      key
    );
    cipherObject.ownerKey = globalThis.btoa(this.ab2str(encryptedKeyOwner));
    */

    for (const recipient of cipherObject.recipients){
      const recipientCryptoKey = await this.prepareKeyforEncryption(recipient.key);
      const encryptedKeyRecipient = await globalThis.crypto.subtle.encrypt(
        { name : "RSA-OAEP" },
        recipientCryptoKey,
        key
      );
      recipient.key = globalThis.btoa(this.ab2str(encryptedKeyRecipient));
    }

    const metaData : EncryptionMetadata = {
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
      recipients: cipherObject.recipients,
      file_type: cipherObject.file_type,
      timestamp: new Date().toISOString(),
    };

    const aad = new TextEncoder().encode(JSON.stringify(metaData));
    const chacha = xchacha20poly1305(key, nonce, aad);
    const cipherText = chacha.encrypt(cipherObject.data);

    return { cipherText, metaData };
  }

  /*
    Implementation Retrieved from:
    https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
  */

  async prepareKeyforDecryption(privateKey: string): Promise<CryptoKey> {
    const binaryDerString = globalThis.atob(privateKey);
    const binaryDer = this.str2ab(binaryDerString);

    return await globalThis.crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"]
    );
  }

  async decrypt_file( metaData: EncryptionMetadata, cipherText: Uint8Array, privateKeyBase64: string, recipientKeyBase64: string): Promise<Uint8Array> {
    const cryptoKey = await this.prepareKeyforDecryption(privateKeyBase64);
    const recipientKey = this.str2ab(atob(recipientKeyBase64));
    const nonce = this.str2ab(atob(metaData.nonce));

    // El recipientKey viene en Hex en la metadata, lo pasamos a bytes
    const symmetricKeyBuffer = await globalThis.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        cryptoKey,
        recipientKey
    );

    const symmetricKey = new Uint8Array(symmetricKeyBuffer);
    const aad = new TextEncoder().encode(JSON.stringify(metaData));

    const chacha = xchacha20poly1305(symmetricKey, new Uint8Array(nonce), aad);
    return chacha.decrypt(cipherText);
  }
}