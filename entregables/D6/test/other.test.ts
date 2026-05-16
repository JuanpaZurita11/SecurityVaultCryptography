import { describe, it, expect} from 'vitest';
import { CipherObject, CryptoModule, SignContainer, b64ToBytes, bytesToB64} from '../src/d6.js';
import { randomBytes } from '@noble/hashes/utils.js';

describe('D6 - TEST EXTRA', () => {
  const cryptoModule: CryptoModule = new CryptoModule();

  const message = "Highly sensitive content";
  const rawData : Uint8Array = new TextEncoder().encode(message);
  const fileType = "text/plain";

  it("Zod module verifications", () => {
    const keyStore = cryptoModule.generate_key_pair("1234");

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt"
    };

    const container: SignContainer = cryptoModule.create_container(keyStore,"1234","Juan",cipherObject);

    expect(cryptoModule.verify_container_structure(container)).toBe(true);
    expect(cryptoModule.verify_key_container_structure(keyStore)).toBe(true);
  });

  it("Multiple recipients", () => {
    const ownerKeyStore = cryptoModule.generate_key_pair("12345");
    const ownerPublicKey = b64ToBytes(ownerKeyStore.public_key);

    const aliceKeyStore = cryptoModule.generate_key_pair("67890");
    const bobKeyStore = cryptoModule.generate_key_pair("1124");

    const cipherObject: CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
        {username: "Alice", publicKey: b64ToBytes(aliceKeyStore.public_key)},
        {username: "Bob", publicKey: b64ToBytes(bobKeyStore.public_key)}
      ]
    };

    const container : SignContainer = cryptoModule.create_container(ownerKeyStore,"12345","Juan",cipherObject);

    const decrytpOwner : Uint8Array = cryptoModule.decrypt_container(container,"Juan",ownerKeyStore,"12345",ownerPublicKey);
    const decrytpAlice : Uint8Array = cryptoModule.decrypt_container(container,"Alice",aliceKeyStore,"67890",ownerPublicKey);
    const decrytpBob : Uint8Array = cryptoModule.decrypt_container(container,"Bob",bobKeyStore,"1124",ownerPublicKey);

    const ownerDec = new TextDecoder().decode(decrytpOwner);
    const aliceDec = new TextDecoder().decode(decrytpAlice);
    const bobDec = new TextDecoder().decode(decrytpBob);

    console.log("Alice decrypted: ", aliceDec);
    console.log("Owner decrypted: ", ownerDec);

    expect(aliceDec).toBe(message);
    expect(bobDec).toBe(message);
    expect(ownerDec).toBe(message);
  });

  it("Remove recipients and add recipients dynamically", () => {
    const ownerKeyStore = cryptoModule.generate_key_pair("12345");
    const ownerPublicKey = b64ToBytes(ownerKeyStore.public_key);

    const aliceKeyStore = cryptoModule.generate_key_pair("67890");
    const bobKeyStore = cryptoModule.generate_key_pair("1124");
    const hankKeyStore = cryptoModule.generate_key_pair("12345");

    const cipherObject: CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
        {username: "Alice", publicKey: b64ToBytes(aliceKeyStore.public_key)},
        {username: "Bob", publicKey: b64ToBytes(bobKeyStore.public_key)}
      ]
    };

    let container : SignContainer = cryptoModule.create_container(ownerKeyStore,"12345","Juan",cipherObject);
    container = cryptoModule.remove_recipients_from_container(container,ownerKeyStore,"12345",["Alice"]);
    container = cryptoModule.add_recipients_to_container(container,ownerKeyStore,"12345",[{username: "Hank", publicKey: b64ToBytes(hankKeyStore.public_key)}]);

    const callback = () => {
      try{
        return cryptoModule.decrypt_container(container,"Alice",aliceKeyStore,"67890",b64ToBytes(ownerKeyStore.public_key));
      } catch(err){
        console.log("Error capturado: ", (err as Error).message);
        throw err;
      }
    }

    const decrytpOwner : Uint8Array = cryptoModule.decrypt_container(container,"Juan",ownerKeyStore,"12345",ownerPublicKey);
    const decrytpBob : Uint8Array = cryptoModule.decrypt_container(container,"Bob",bobKeyStore,"1124",ownerPublicKey);
    const decryptHank: Uint8Array = cryptoModule.decrypt_container(container,"Hank",hankKeyStore,"12345",ownerPublicKey);

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
  });

  it("allow KeyStorage password change without breaking acces to the containers", () => {
    const ownerKeyStore = cryptoModule.generate_key_pair("12345");
    const ownerPublicKey = b64ToBytes(ownerKeyStore.public_key);

    let aliceKeyStore = cryptoModule.generate_key_pair("67890");
    const cipherObject: CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
      recipients: [
        {username: "Alice", publicKey: b64ToBytes(aliceKeyStore.public_key)},
      ]
    };

    const container : SignContainer = cryptoModule.create_container(ownerKeyStore,"12345","Juan",cipherObject);

    aliceKeyStore = cryptoModule.update_keystorage_password(aliceKeyStore,"67890","12345");

    const decrytpOwner : Uint8Array = cryptoModule.decrypt_container(container,"Juan",ownerKeyStore,"12345",ownerPublicKey);
    const decrytpAlice : Uint8Array = cryptoModule.decrypt_container(container,"Alice",aliceKeyStore,"12345",ownerPublicKey);


    const ownerDec = new TextDecoder().decode(decrytpOwner);
    const aliceDec= new TextDecoder().decode(decrytpAlice);


    console.log("Owner decrypted: ", ownerDec);
    console.log("Alice decrypted: ", aliceDec);

    expect(ownerDec).toBe(message);
    expect(aliceDec).toBe(message);

    const callback = () => {
      try{
        return cryptoModule.update_keystorage_password(aliceKeyStore,"985432","67890");
      }catch(err){
        console.log("Error capturado: ", (err as Error).message);
        throw err;
      }
    }
    expect(callback).toThrow();
  },7000);

});
