import { describe, it, expect} from 'vitest';
import { KeyManager } from '../src/key_manager.js';
import { CipherObject, SignatureCryptoModule, SignContainer, bytesToB64} from '../src/signature_crypto_module.js';
import { sha256 } from '@noble/hashes/webcrypto.js';


describe('SignatureCryptoModule Integrity Tests', () => {
  const keyManager: KeyManager = new KeyManager();
  const signatureModule: SignatureCryptoModule = new SignatureCryptoModule();

  const message = "Highly sensitive content";
  const rawData = new TextEncoder().encode(message);
  const fileType = "text/plain";


  it('should allow multiple recipients to decrypt the message', () => {
    const ownerKeys = keyManager.generate_key_pair();
    const user1Keys = keyManager.generate_key_pair();
    const user2Keys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
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

    const decrypted1 : Uint8Array = signatureModule.decrypt_container(
      container,
      'Alice',
      user1Keys.privateKey,
      ownerKeys.publicKey
    );


    const decrypted2 : Uint8Array = signatureModule.decrypt_container(
      container,
      'Bob',
      user2Keys.privateKey,
      ownerKeys.publicKey
    );

    //Owner
    const decryptedOwner : Uint8Array = signatureModule.decrypt_container(
      container,
      'Juan',
      ownerKeys.privateKey,
      ownerKeys.publicKey
    );

    const aliceDecrypted = new TextDecoder().decode(decrypted1);
    const bobDecrypted = new TextDecoder().decode(decrypted2);
    const ownerDecrypted = new TextDecoder().decode(decryptedOwner);

    console.log("Alice decrypted:", aliceDecrypted);
    console.log("Bob decrypted:", bobDecrypted);
    console.log("Owner decrypted:", ownerDecrypted);

    expect(aliceDecrypted).toBe(message);
    expect(bobDecrypted).toBe(message);
    expect(ownerDecrypted).toBe(message);
  });

  it('should acccept a valid signature', async () => {

    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt"
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    const fingerprintOwner = bytesToB64( await sha256(ownerKeys.publicKey) );

    expect(container.metaData.owner_fingerprint).toBe(fingerprintOwner);
    expect(signatureModule.validate_container_signature(container, ownerKeys.publicKey)).toBe(true);
  });

  it('should reject when ciphertext is modified', () => {

    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt"
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    // Modificar el ciphertext (cambiamos el último carácter antes del tag)
    const original = container.cipherText_w_tag;
    container.cipherText_w_tag = original.substring(0, original.length - 1) + (original.endsWith('A') ? 'B' : 'A');

    expect(signatureModule.validate_container_signature(container, ownerKeys.publicKey)).toBe(false);
  });

  it('should reject when metadata is modified', () => {

    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt"
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    // Alterar la metadata (ej. cambiar el timestamp o el tipo de archivo)
    container.metaData.file_type = "application/malicious";

    expect(signatureModule.validate_container_signature(container, ownerKeys.publicKey)).toBe(false);
  });

  it('should reject when the wrong public key is used for container signature validation', () => {
    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
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

    expect(signatureModule.validate_container_signature(container, attackerKeys.publicKey)
    ).toBe(false);
  });


  it('should reject when a recipient wrong public key is used for decrypt', () => {
    const ownerKeys = keyManager.generate_key_pair();
    const user1Keys = keyManager.generate_key_pair();
    const user2Keys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
        { username: 'Alice', publicKey: user1Keys.publicKey },
      ]
    };

    const container: SignContainer = signatureModule.create_container(
      ownerKeys.privateKey,
      ownerKeys.publicKey,
      "Juan",
      cipherObject
    );

    const callback = () => {
      try{
        return signatureModule.decrypt_container(container,'Alice',user2Keys.privateKey,ownerKeys.publicKey);
      } catch(err){
        console.log("Error capturado: ", (err as Error).message);
        throw err;
      }
    }
    expect(callback).toThrow();

  });

  it('should fail if signature is removed or missing', () => {
    const ownerKeys = keyManager.generate_key_pair();

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
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

    const callback = () => {
      try{
        return signatureModule.validate_container_signature(container, ownerKeys.publicKey);
      } catch(err){
        console.log("Error capturado: ", (err as Error).message);
        throw err;
      }
    }

    expect(callback).toThrow();
  });

  it('should allow the decryption even after exporting and importing keys', async () => {
    const ownerKeys = keyManager.generate_key_pair();

    const publicPem = await keyManager.serialize_public_key_pem(ownerKeys.publicKey);
    const privatePem = await keyManager.serialize_private_key_pem(ownerKeys.privateKey);

    const importedPublicKey = await keyManager.deserialize_public_key_pem(publicPem);
    const importedPrivateKey = await keyManager.deserialize_private_key_pem(privatePem);

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
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


    const decryptedOwner : Uint8Array = signatureModule.decrypt_container(
      container,
      'Juan',
      importedPrivateKey,
      importedPublicKey
    );

    const ownerDecrypted = new TextDecoder().decode(decryptedOwner);
    console.log("Owner decrypted:", ownerDecrypted);

    expect(ownerDecrypted).toBe(message);
  });

  it("Remove recipients and add recipients dynamically", () => {

		const ownerKeys= keyManager.generate_key_pair();
		const aliceKeys = keyManager.generate_key_pair();
		const bobKeys = keyManager.generate_key_pair();
		const hankKeys = keyManager.generate_key_pair();

		const cipherObject: CipherObject = {
			data: rawData,
			file_type: fileType,
			filename: "secret.txt",
			recipients: [
				{
					username: "Alice",
					publicKey: aliceKeys.publicKey,
				},
				{
					username: "Bob",
					publicKey: bobKeys.publicKey,
				},
			],
		};

		let container: SignContainer = signatureModule.create_container(
			ownerKeys.privateKey,
			ownerKeys.publicKey,
			"Juan",
			cipherObject,
		);
		container = signatureModule.remove_recipients_from_container(
			container,
			ownerKeys.publicKey,
			ownerKeys.privateKey,
			["Alice"],
		);
		container = signatureModule.add_recipients_to_container(
			container,
			ownerKeys.publicKey,
      ownerKeys.privateKey,
			[
				{
					username: "Hank",
					publicKey: hankKeys.publicKey,
				},
			],
		);

		const callback = () => {
			try {
				return signatureModule.decrypt_container(
					container,
					"Alice",
					aliceKeys.privateKey,
          ownerKeys.publicKey
				);
			} catch (err) {
				console.log("Error capturado: ", (err as Error).message);
				throw err;
			}
		};

		const decrytpOwner: Uint8Array = signatureModule.decrypt_container(
			container,
			"Juan",
			ownerKeys.privateKey,
			ownerKeys.publicKey,
		);
		const decrytpBob: Uint8Array = signatureModule.decrypt_container(
			container,
			"Bob",
			bobKeys.privateKey,
			ownerKeys.publicKey,
		);
		const decryptHank: Uint8Array = signatureModule.decrypt_container(
			container,
			"Hank",
			hankKeys.privateKey,
			ownerKeys.publicKey,
		);

		const ownerDec = new TextDecoder().decode(decrytpOwner);
		const bobDec = new TextDecoder().decode(decrytpBob);
		const hankDec = new TextDecoder().decode(decryptHank);

		console.log("Bob decrypted: ", bobDec);
		console.log("Owner decrypted: ", ownerDec);
		console.log("Hank decrypted: ", hankDec);

		expect(callback).toThrow();
		expect(bobDec).toBe(message);
		expect(ownerDec).toBe(message);
		expect(hankDec).toBe(message);
	}, 15000);

});
