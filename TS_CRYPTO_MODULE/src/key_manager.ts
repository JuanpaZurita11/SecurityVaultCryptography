import { ed25519 } from "@noble/curves/ed25519.js";
import { b64ToBytes, bytesToB64 } from "./signature_crypto_module.js";

export class KeyManager {

  generate_key_pair(): {publicKey: Uint8Array; privateKey: Uint8Array}{
    const keyPair = ed25519.keygen();
    return {publicKey: keyPair.publicKey, privateKey: keyPair.secretKey};
  }

  // ----- EXPORT -------

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
    // Construir PKCS#8 DER manualmente para Ed25519
    // Estructura fija de 48 bytes — RFC 8410
    const der = new Uint8Array([
      0x30, 0x2e,              // SEQUENCE (46 bytes)
        0x02, 0x01, 0x00,      //   INTEGER version = 0
        0x30, 0x05,            //   SEQUENCE AlgorithmIdentifier
          0x06, 0x03,          //     OID tag + length
          0x2b, 0x65, 0x70,    //     OID 1.3.101.112 (Ed25519)
        0x04, 0x22,            //   OCTET STRING (34 bytes) outer
          0x04, 0x20,          //     OCTET STRING (32 bytes) inner
          ...rawKey            //     raw key bytes
    ]);

    const exportedAsBase64 = bytesToB64(der);
    return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
  }

  // IMPORTAR

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

  async deserialize_private_key_pem(pem: string): Promise<Uint8Array> {
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';

    if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
      throw new Error('La clave no tiene estructura PEM');
    }

    const pemContents = pem
      .substring(pemHeader.length, pem.length - pemFooter.length)
      .replace(/\s/g, '');

    const binaryDer = b64ToBytes(pemContents);

    // Importar para validar que el PEM es correcto
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'pkcs8',
      binaryDer.buffer as ArrayBuffer,
      'Ed25519',
      true,
      ['sign']
    );

    const exportedDer = new Uint8Array(
      await globalThis.crypto.subtle.exportKey('pkcs8', cryptoKey)
    );

    return exportedDer.slice(16);
  }
}
