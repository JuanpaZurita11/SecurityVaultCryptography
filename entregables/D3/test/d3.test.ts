import { describe, it, expect} from 'vitest';
import { KeyManager, HybridEncryption, CipherObject, Container } from '../src/d3.js';


describe('SignatureCryptoModule Integrity Tests', () => {
  const keyManager: KeyManager = new KeyManager();
  const HybridModule: HybridEncryption = new HybridEncryption();

  const message = "Highly sensitive content";
  const rawData = new TextEncoder().encode(message);
  const fileType = "text/plain";


  it('should allow multiple recipients to decrypt the message', async () => {

    const ownerKeys = await keyManager.generate_key_pair();
    const user1Keys = await keyManager.generate_key_pair();
    const user2Keys = await keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey },
        { username: 'Alice', publicKey: user1Keys.publicKey },
        { username: 'Bob', publicKey: user2Keys.publicKey }
      ]
    };

    const container: Container = await HybridModule.encrypt_file(
      cipherObject
    );

    const decrypted1 : Uint8Array = await HybridModule.decrypt_file(
      container,
      'Alice',
      user1Keys.privateKey
    );

    const decrypted2 : Uint8Array = await HybridModule.decrypt_file(
      container,
      'Bob',
      user2Keys.privateKey,
    );


    const aliceDecrypted = new TextDecoder().decode(decrypted1);
    const bobDecrypted = new TextDecoder().decode(decrypted2);

    console.log("Alice decrypted:", aliceDecrypted);
    console.log("Bob decrypted:", bobDecrypted);

    expect(aliceDecrypted).toBe(message);
    expect(bobDecrypted).toBe(message);

  });

  it('should reject unauthorized user', async () => {
    const ownerKeys = await keyManager.generate_key_pair();
    const aliceKeys = await keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey }
      ]
    };

    const container: Container = await HybridModule.encrypt_file(
      cipherObject
    );


    await expect(HybridModule.decrypt_file(container, 'Alice', aliceKeys.privateKey).catch(err => {console.log(err.message); throw err})).rejects.toThrow();
  });

  it('should fail decryption when the recipient list is tampered with', async () => {

    const ownerKeys = await keyManager.generate_key_pair();
    const aliceKeys = await keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey },
        { username: 'Alice', publicKey: aliceKeys.publicKey }
      ]
    };

    const container: Container = await HybridModule.encrypt_file(
      cipherObject
    );

    container.metaData.recipients[0].username = 'Eve'; // Cambiar el destinatario de Juan a Eve

    await expect(HybridModule.decrypt_file(container, 'Alice', aliceKeys.privateKey).catch(err => {console.log(err.message); throw err})).rejects.toThrow();
  });

  it('should fail decryption when using wrong private key', async () => {

    const ownerKeys = await keyManager.generate_key_pair();
    const aliceKeys = await keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey },
        { username: 'Alice', publicKey: aliceKeys.publicKey }
      ]
    };

    const container: Container = await HybridModule.encrypt_file(
      cipherObject
    );

    await expect(HybridModule.decrypt_file(container, 'Juan', aliceKeys.privateKey).catch(err => {console.log(err.message); throw err})).rejects.toThrow();
  });

  it('should fail decryption when recipient entry is missing', async () => {
    const ownerKeys = await keyManager.generate_key_pair();
    const aliceKeys = await keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey },
        { username: 'Alice', publicKey: aliceKeys.publicKey }
      ]
    };

    const container: Container = await HybridModule.encrypt_file(
      cipherObject
    );

    container.metaData.recipients.pop(); // Eliminar la entrada de Alice

    await expect(HybridModule.decrypt_file(container, 'Juan', ownerKeys.privateKey).catch(err => {console.log(err.message); throw err})).rejects.toThrow();
  });


  it('should allow the decryption even after exporting and importing keys', async () => {
    const ownerKeys = await keyManager.generate_key_pair();
    const privatePem = await keyManager.exportPrivateKey(ownerKeys.privateKey);
    const importedPrivateKey : CryptoKey = await keyManager.importPrivateKey(privatePem);

    const aliceKeys = await keyManager.generate_key_pair();
    const alicePrivatePem = await keyManager.exportPrivateKey(aliceKeys.privateKey);
    const importedAlicePrivateKey : CryptoKey = await keyManager.importPrivateKey(alicePrivatePem);

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
        { username: 'Juan', publicKey: ownerKeys.publicKey },
        { username: 'Alice', publicKey: aliceKeys.publicKey }
      ]
    };

    const container: Container = await HybridModule.encrypt_file(
      cipherObject
    );

    const decryptedAlice : Uint8Array = await HybridModule.decrypt_file(
      container,
      'Alice',
      importedAlicePrivateKey
    );

    const decryptedJuan : Uint8Array = await HybridModule.decrypt_file(
      container,
      'Juan',
      importedPrivateKey
    );

    const aliceDecrypted = new TextDecoder().decode(decryptedAlice);
    const juanDecrypted = new TextDecoder().decode(decryptedJuan);

    console.log("Alice decrypted:", aliceDecrypted);
    console.log("Juan decrypted:", juanDecrypted);

    expect(aliceDecrypted).toBe(message);
    expect(juanDecrypted).toBe(message);
  });

});
