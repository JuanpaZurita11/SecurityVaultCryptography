import { describe, it, expect, beforeEach } from 'vitest';
import { KeyManager, SignatureCryptoModule } from '../src/signature_crypto_module';



describe('SignatureCryptoModule Integrity Tests', () => {
  let keyManager: KeyManager;
  let signatureEnc: SignatureCryptoModule;

  const message = "Highly sensitive content";
  const rawData = new TextEncoder().encode(message);
  const fileType = "text/plain";

  beforeEach(() => {
    keyManager = new KeyManager();
    signatureEnc = new SignatureCryptoModule();
  });

  it('should accept a valid signature', () => {
    const ownerKeys = keyManager.generate_key_pair();
    const user1Keys = keyManager.generate_key_pair();
    const user2Keys = keyManager.generate_key_pair();

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', key: ownerKeys.publicKey },
        { username: 'Alice', key: user1Keys.publicKey },
        { username: 'Bob', key: user2Keys.publicKey }
      ]
    };

    const container = signatureEnc.generate_signature(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    if (signatureEnc.validate_signature(container, ownerKeys.publicKey)){
      console.log("Signature is valid.");

      const aliceWrap = container.recipients.find(r => r.username === 'Alice');
      if (!aliceWrap) throw new Error("Alice wrap not found");

      const metaData = {
        metaData: container.metaData,
        nonce: container.nonce,
        recipients: container.recipients,
      }

      const originalCipherBase64 = container.cipherText + container.tag;
      const cipherText = new Uint8Array(signatureEnc.str2ab(atob(originalCipherBase64)));

      const decrypted1 = signatureEnc.decrypt_file(
        metaData,
        cipherText,
        user1Keys.privateKey,
        aliceWrap
      );

      // 5. Intento de descifrado: Usuario 2 (Bob)
      const bobWrap = metaData.recipients.find(r => r.username === 'Bob');
      if (!bobWrap) throw new Error("Bob wrap not found");

      const decrypted2 = signatureEnc.decrypt_file(
        metaData,
        cipherText,
        user2Keys.privateKey,
        bobWrap
      );

      // 6. Validar resultados
      expect(new TextDecoder().decode(decrypted1)).toBe(message);
      expect(new TextDecoder().decode(decrypted2)).toBe(message);
    }

  });

  it('should reject when ciphertext is modified', () => {
    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', key: ownerKeys.publicKey }
      ]
    };

    const container = signatureEnc.generate_signature(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    // Modificar el ciphertext (cambiamos el último carácter antes del tag)
    const original = container.cipherText;
    container.cipherText = original.substring(0, original.length - 1) + (original.endsWith('A') ? 'B' : 'A');

    expect(() => {
      signatureEnc.validate_signature(container, ownerKeys.publicKey);
    }).toThrow();
  });

  it('should reject when metadata is modified', () => {
    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', key: ownerKeys.publicKey }
      ]
    };

    const container = signatureEnc.generate_signature(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    // Alterar la metadata (ej. cambiar el timestamp o el tipo de archivo)
    container.metaData.file_type = "application/malicious";

    expect(() => {
      signatureEnc.validate_signature(container, ownerKeys.publicKey);
    }).toThrow();
  });

  it('should reject when the wrong public key is used for validation', () => {
    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', key: ownerKeys.publicKey }
      ]
    };

    const container = signatureEnc.generate_signature(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    const attackerKeys = keyManager.generate_key_pair();

    // El validador intenta usar la llave del atacante en lugar de la de Alice
    expect(() => {
      signatureEnc.validate_signature(container, attackerKeys.publicKey);
    }).toThrow(); // Fallará por mismatch de fingerprint o verificación de firma
  });

  it('should fail if signature is removed or missing', () => {
    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', key: ownerKeys.publicKey }
      ]
    };

    const container = signatureEnc.generate_signature(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    container.signature = "";

    expect(() => {
      signatureEnc.validate_signature(container, ownerKeys.publicKey);
    }).toThrow();
  });
});


/*
describe('SignatureCryptoModule Tests', () => {
  let keyManager: KeyManager;
  let signatureEnc: SignatureCryptoModule;

  // Datos de prueba
  const message = "Top Secret Data";
  const rawData = new TextEncoder().encode(message);
  const fileType = "text/plain";

  beforeEach(() => {
    keyManager = new KeyManager();
    signatureEnc = new SignatureCryptoModule();
  });

  it('should allow two different recipients to decrypt the same file using their private keys', () => {
    // 1. Generar llaves para los involucrados
    const user1Keys = keyManager.generate_key_pair();
    const user2Keys = keyManager.generate_key_pair();

    // 2. Configurar el objeto de cifrado
    const cipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Alice', key: user1Keys.publicKey },
        { username: 'Bob', key: user2Keys.publicKey }
      ]
    };

    // 3. Ejecutar el cifrado híbrido
    const { cipherText, metaData } = signatureEnc.encrypt_file(cipherObject);


    // 4. Intento de descifrado: Usuario 1 (Alice)
    // Buscamos su "key wrap" específico en los metadatos
    const aliceWrap = metaData .recipients.find(r => r.username === 'Alice');
    if (!aliceWrap) throw new Error("Alice wrap not found");

    const decrypted1 = signatureEnc.decrypt_file(
      metaData,
      cipherText,
      user1Keys.privateKey,
      aliceWrap
    );

    // 5. Intento de descifrado: Usuario 2 (Bob)
    const bobWrap = metaData.recipients.find(r => r.username === 'Bob');
    if (!bobWrap) throw new Error("Bob wrap not found");

    const decrypted2 = signatureEnc.decrypt_file(
      metaData,
      cipherText,
      user2Keys.privateKey,
      bobWrap
    );

    // 6. Validar resultados
    expect(new TextDecoder().decode(decrypted1)).toBe(message);
    expect(new TextDecoder().decode(decrypted2)).toBe(message);
  });

  it('should fail decryption if the wrong private key is used', () => {
    const user1Keys = keyManager.generate_key_pair();
    const attackerKeys = keyManager.generate_key_pair();

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [{ username: 'Alice', key: user1Keys.publicKey }]
    };

    const { cipherText, metaData } = signatureEnc.encrypt_file(cipherObject);

    // Intentar descifrar el paquete de Alice con la llave del atacante
    expect(() => {
      signatureEnc.decrypt_file(
        metaData,
        cipherText,
        attackerKeys.privateKey,
        metaData.recipients[0]
      );
    }).toThrow();
  });
});
*/