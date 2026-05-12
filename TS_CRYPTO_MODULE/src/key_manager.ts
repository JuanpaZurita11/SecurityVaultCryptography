import { ed25519 } from "@noble/curves/ed25519.js";
import { b64ToBytes, bytesToB64 } from "./signature_crypto_module.js";

export class KeyManager {

  generate_key_pair(): {publicKey: Uint8Array; privateKey: Uint8Array}{
    const keyPair = ed25519.keygen();
    return {publicKey: keyPair.publicKey, privateKey: keyPair.secretKey};
  }

  async serialize_public_key_pem(rawKey: Uint8Array): Promise<string>{
    const spkiObject : CryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      rawKey.buffer as ArrayBuffer,
      "Ed25519",
      true,
      []
    );
    const spkiDer = await globalThis.crypto.subtle.exportKey("spki", spkiObject);

    const exportedAsBase64 = bytesToB64(new Uint8Array(spkiDer));
    return  `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
  }


  async serialize_private_key_pem(rawKey: Uint8Array): Promise<string> {
    // PKCS#8 header fijo para Ed25519 (RFC 8410)
    const pkcs8Header = new Uint8Array([
      0x30, 0x2e,       // SEQUENCE (46 bytes)
      0x02, 0x01, 0x00, // INTEGER 0 (version)
      0x30, 0x05,       // SEQUENCE (5 bytes) - AlgorithmIdentifier
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
      0x04, 0x22,       // OCTET STRING (34 bytes)
        0x04, 0x20,     // OCTET STRING (32 bytes) - la clave en sí
    ]);

    // Concatenar header + rawKey (32 bytes)
    const pkcs8Der = new Uint8Array(pkcs8Header.length + rawKey.length);
    pkcs8Der.set(pkcs8Header);
    pkcs8Der.set(rawKey, pkcs8Header.length);

    const exportedAsBase64 = bytesToB64(pkcs8Der);
    return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
  }

  async deserialize_public_key_pem(pem: string): Promise<Uint8Array>{
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
      "Ed25519",
      true,
      []
    );

    const rawKey = await globalThis.crypto.subtle.exportKey("raw", cryptoKey);
    return new Uint8Array(rawKey);
  }

  async deserialize_private_key_pem(pem: string): Promise<Uint8Array>{
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
      "Ed25519",
      true,
      []
    );

    const rawKey = await globalThis.crypto.subtle.exportKey("raw", cryptoKey);
    return new Uint8Array(rawKey);
  }
}
