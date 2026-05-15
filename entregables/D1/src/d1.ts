import { randomBytes } from "@noble/ciphers/utils.js";
import { xchacha20poly1305  } from '@noble/ciphers/chacha.js';
import stringify  from 'fast-json-stable-stringify';


export interface CipherObject{
  data : Uint8Array;
  filename: string;
  file_type: string;
}

interface MetaData{
  filename: string;
  file_type: string;
  timestamp: string;
  encryption: "Symmetric";
  parameters:{
    cipher: "XChacha20+Poly1305";
    key_size_bits: 256;
    nonce_size_bytes: 24;
    tag_size_bytes: 16
  }
  nonce: string;
}

export interface Container{
  metaData: MetaData;
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


export class SymmetricEncryption {

  generate_symmetric_key(): Uint8Array{
    return randomBytes(32);
  }

  encrypt_file(cipherObject: CipherObject): {container: Container, symmetricKey: Uint8Array}{

    const key = randomBytes(32);
    const nonce = randomBytes(24);


    const metaData : MetaData = {
      filename: cipherObject.filename,
      file_type: cipherObject.file_type,
      timestamp: new Date().toISOString(),
      encryption: "Symmetric",
      parameters: {
        cipher: "XChacha20+Poly1305",
        key_size_bits: 256,
        nonce_size_bytes: 24,
        tag_size_bytes: 16
      },
      nonce: bytesToB64(nonce),
    };

    const aad = new TextEncoder().encode(stringify(metaData));
    const chacha = xchacha20poly1305(key, nonce, aad);
    const cipherText_w_tag = chacha.encrypt(cipherObject.data);

    const container : Container = {
      metaData,
      cipherText_w_tag: bytesToB64(cipherText_w_tag)
    }

    return { container, symmetricKey: key};
  }

  decrypt_file( container: Container, symmetricKey: Uint8Array): Uint8Array {

      const nonce = b64ToBytes(container.metaData.nonce);

      const aad = new TextEncoder().encode(stringify(container.metaData));

      const chacha = xchacha20poly1305(symmetricKey,nonce,aad);

      const data_ = b64ToBytes(container.cipherText_w_tag);

      return chacha.decrypt(data_);
  }

}

