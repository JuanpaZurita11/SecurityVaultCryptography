import { describe, it, expect} from 'vitest';
import { CipherObject, CryptoModule, SignContainer, b64ToBytes, bytesToB64} from '../src/d6.js';
import { randomBytes } from '@noble/hashes/utils.js';


describe('D6 - Test PART 1', () => {
  const cryptoModule: CryptoModule = new CryptoModule();

  const message = "Highly sensitive content";
  const rawData : Uint8Array = new TextEncoder().encode(message);
  const fileType = "text/plain";

  it("correct password = access granted", () => {
    const ownerKeys = cryptoModule.generate_key_pair("12345");
    const ownerPublicKey = b64ToBytes(ownerKeys.public_key);

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt"
    };

    const container: SignContainer = cryptoModule.create_container(ownerKeys,"12345","Juan",cipherObject);
    console.log(JSON.stringify(container));

    const decrypted : Uint8Array = cryptoModule.decrypt_container(container,"Juan",ownerKeys,"12345",ownerPublicKey);

    const data_ = new TextDecoder().decode(decrypted);
    console.log(data_);
    expect(data_).toBe(message);
  });

  it("wrong password = access denied", () => {
    const ownerKeys = cryptoModule.generate_key_pair("12345");
    const ownerPublicKey = b64ToBytes(ownerKeys.public_key);


    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
    };

    const container: SignContainer = cryptoModule.create_container(ownerKeys,"12345","Juan",cipherObject);

    const callback = () =>{
      try{
        return cryptoModule.decrypt_container(container,"Juan",ownerKeys,"123456",ownerPublicKey); //Contraseña incorrecta
      }catch(err){
        console.error("Error capturado: ", (err as Error).message);
        throw Error;
      }
    };

    expect(callback).toThrow();
  });

  it("Modfied Keystore = failure", () => {
    const keyStore = cryptoModule.generate_key_pair("12345");
    const corruptKeyStore = {...keyStore};

    const publicKey = cryptoModule.getPublicKey(keyStore);

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt"
    };

    const container: SignContainer = cryptoModule.create_container(keyStore,"12345","Juan",cipherObject);

    //DOS CASOS

    //1. Estructura errónea
    delete (corruptKeyStore as any).metadata;

    //2. Alteración de una propiedad
    keyStore.nonce = bytesToB64(randomBytes(24));
    const callback = () => {
      try{
        return cryptoModule.decrypt_container(container,"Juan",keyStore,"12345",publicKey);
      }catch(err){
        console.error("Error capturado:", (err as Error).message);
        throw Error;
      }
    }

    expect(cryptoModule.verify_key_container_structure(corruptKeyStore)).toBe(false);
    expect(callback).toThrow();
  });
});
