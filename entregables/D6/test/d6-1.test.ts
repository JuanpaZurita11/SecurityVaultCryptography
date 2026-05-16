import { describe, it, expect} from 'vitest';
import { CipherObject, CryptoModule, SignContainer, b64ToBytes} from '../src/d6.js';


describe('D6 - Test PART 2', () => {
  const cryptoModule: CryptoModule = new CryptoModule();

  const message = "Highly sensitive content";
  const rawData : Uint8Array = new TextEncoder().encode(message);
  const fileType = "text/plain";

  it("allow key recipients updates without breaking the container", () => {
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

    const newAliceKeyStore = cryptoModule.generate_key_pair("45678");
    const newBobKeyStore = cryptoModule.generate_key_pair("09876");


    container = cryptoModule.add_recipients_to_container(container,ownerKeyStore,"12345",[{username: "Hank", publicKey: b64ToBytes(hankKeyStore.public_key)}]);
    container = cryptoModule.update_container_recipientKeys(container,ownerKeyStore,"12345",
      [{username: "Alice", publicKey: b64ToBytes(newAliceKeyStore.public_key)},
        {username: "Bob", publicKey: b64ToBytes(newBobKeyStore.public_key)}
      ]
    );

    const callback = () => {
      try{
        return cryptoModule.decrypt_container(container,"Alice",aliceKeyStore,"67890",b64ToBytes(ownerKeyStore.public_key));
      } catch(err){
        console.log("Error capturado: ", (err as Error).message);
        throw err;
      }
    }

    const decrytpOwner : Uint8Array = cryptoModule.decrypt_container(container,"Juan",ownerKeyStore,"12345",ownerPublicKey);
    const decrytpAlice : Uint8Array = cryptoModule.decrypt_container(container,"Alice",newAliceKeyStore,"45678",ownerPublicKey);
    const decryptHank: Uint8Array = cryptoModule.decrypt_container(container,"Hank",hankKeyStore,"12345",ownerPublicKey);
    const decrytpBob : Uint8Array = cryptoModule.decrypt_container(container,"Bob",newBobKeyStore,"09876",ownerPublicKey);

    const ownerDec = new TextDecoder().decode(decrytpOwner);
    const aliceDec = new TextDecoder().decode(decrytpAlice);
    const hankDec = new TextDecoder().decode(decryptHank);
    const bobDec = new TextDecoder().decode(decrytpBob);

    console.log("Alice decrypted: ", aliceDec);
    console.log("Owner decrypted: ", ownerDec);
    console.log("Hank decrypted: ", hankDec);
    console.log("Bob decrypted: ", bobDec);

    expect(callback).toThrow();
    expect(aliceDec).toBe(message);
    expect(ownerDec).toBe(message);
    expect(hankDec).toBe(message);

  }, 10000);

});