import { describe, it, expect, beforeEach } from 'vitest';
import { KeyManager } from '../src/key_manager.js';
import { b64ToBytes, CipherObject, EncryptionMetadata, SignatureCryptoModule, SignContainer} from '../src/signature_crypto_module.js';
import { KeyWrap } from '../src/signature_crypto_module.js';


describe('SignatureCryptoModule Integrity Tests', () => {
  let keyManager: KeyManager;
  let signatureModule: SignatureCryptoModule;

  const message = "Highly sensitive content";
  const rawData = new TextEncoder().encode(message);
  const fileType = "text/plain";

  beforeEach(() => {
    keyManager = new KeyManager();
    signatureModule = new SignatureCryptoModule();
  });

  it('should allow multiple recipients to decrypt the message', () => {
    const ownerKeys = keyManager.generate_key_pair();
    const user1Keys = keyManager.generate_key_pair();
    const user2Keys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey },
        { username: 'Alice', publicKey: user1Keys.publicKey },
        { username: 'Bob', publicKey: user2Keys.publicKey }
      ]
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    // Se verifica que el contenedor sea válido antes de intentar el descifrado

    if (signatureModule.verify_container(container, ownerKeys.publicKey)){

      const metaData : EncryptionMetadata = {
        ...container.metaData
      }

      const cipherText = b64ToBytes(container.cipherText);

      const aliceWrap = container.metaData.recipients.find( (r : KeyWrap)=> r.username === 'Alice');
      if (!aliceWrap) throw new Error("Alice wrap not found");


      const decrypted1 = signatureModule.decrypt_file(
        cipherText,
        metaData,
        user1Keys.privateKey,
        aliceWrap
      );

      const bobWrap = metaData.recipients.find( (r : KeyWrap)=> r.username === 'Bob');
      if (!bobWrap) throw new Error("Bob wrap not found");

      const decrypted2 = signatureModule.decrypt_file(
        cipherText,
        metaData,
        user2Keys.privateKey,
        bobWrap
      );

      const aliceDecrypted = new TextDecoder().decode(decrypted1);
      const bobDecrypted = new TextDecoder().decode(decrypted2);
      console.log("Alice decrypted:", aliceDecrypted);
      console.log("Bob decrypted:", bobDecrypted);

      expect(aliceDecrypted).toBe(message);
      expect(bobDecrypted).toBe(message);
    }

  });

  it('should acccept a valid signature', () => {
    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey }
      ]
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    expect(signatureModule.verify_container(container, ownerKeys.publicKey)).toBe(true);
  });

  it('should reject when ciphertext is modified', () => {

    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey }
      ]
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    // Modificar el ciphertext (cambiamos el último carácter antes del tag)
    const original = container.cipherText;
    container.cipherText = original.substring(0, original.length - 1) + (original.endsWith('A') ? 'B' : 'A');

    expect(signatureModule.verify_container(container, ownerKeys.publicKey)).toBe(false);
  });

  it('should reject when metadata is modified', () => {

    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey }
      ]
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    // Alterar la metadata (ej. cambiar el timestamp o el tipo de archivo)
    container.metaData.file_type = "application/malicious";

    expect(signatureModule.verify_container(container, ownerKeys.publicKey)).toBe(false);
  });

  it('should reject when the wrong public key is used for container signature validation', () => {
    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey }
      ]
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    const attackerKeys = keyManager.generate_key_pair();

    // El validador intenta usar la llave del atacante en lugar de la de Alice
    expect(signatureModule.verify_container(container, attackerKeys.publicKey)
    ).toBe(false);
  });


  it('should reject when a recipient wrong public key is used for decrypt', () => {
    const ownerKeys = keyManager.generate_key_pair();
    const user1Keys = keyManager.generate_key_pair();
    const user2Keys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey },
        { username: 'Alice', publicKey: user1Keys.publicKey },
      ]
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    // Se verifica que el contenedor sea válido antes de intentar el descifrado

    if (signatureModule.verify_container(container, ownerKeys.publicKey)){

      const metaData : EncryptionMetadata = {
        ...container.metaData
      }

      const cipherText = b64ToBytes(container.cipherText);

      const aliceWrap = container.metaData.recipients.find( (r : KeyWrap)=> r.username === 'Alice');
      if (!aliceWrap) throw new Error("Alice wrap not found");

      expect(
        () => {
          signatureModule.decrypt_file(
            cipherText,
            metaData,
            user2Keys.privateKey,
            aliceWrap
          );
        }
      ).toThrow();

    }
  });

  it('should fail if signature is removed or missing', () => {
    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey }
      ]
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    delete (container as any).signature; // Eliminar la firma

    expect(() => {
      signatureModule.verify_container(container, ownerKeys.publicKey);
    }).toThrow();
  });
});
