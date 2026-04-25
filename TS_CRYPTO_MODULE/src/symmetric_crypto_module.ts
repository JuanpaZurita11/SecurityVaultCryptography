import { randomBytes } from "@noble/ciphers/utils.js";
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';


interface MetaData {
  encryption: string;
  parameters: {
    cipher: string;
    key_size_bits: number;
    nonce_size_bytes: number;
    tag_size_bytes: number;
  };
  nonce: string;      // base64
  timestamp: string;  // ISO string
}

export class SymmetricEncryption {

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

  async encrypt_file(file: Uint8Array){

    const key = randomBytes(32);
    const nonce = randomBytes(24);


    const metaData = {
      encryption: "Symmetric",
      parameters: {
        cipher: "XChacha20-Poly1305",
        key_size_bits: 256,
        nonce_size_bytes: 24,
        tag_size_bytes: 16
      },
      nonce: btoa(String.fromCharCode(...nonce)),
      timestamp: new Date().toISOString(),
    };

    const aad = new TextEncoder().encode(JSON.stringify(metaData));
    const chacha = xchacha20poly1305(key, nonce, aad);
    const cipherText = chacha.encrypt(file);

    const symmetric_key = btoa(String.fromCharCode(...key));

    return { cipherText, metaData, symmetric_key};
  }

  async decrypt_file( metaData: MetaData, cipherText: Uint8Array, key: string): Promise<Uint8Array> {

      const nonce = this.str2ab(atob(metaData.nonce));
      const symmetric_key = this.str2ab(atob(key));

      const aad = new TextEncoder().encode(JSON.stringify(metaData));
      const chacha = xchacha20poly1305(new Uint8Array(symmetric_key), new Uint8Array(nonce), aad);
      return chacha.decrypt(cipherText);
  }
}