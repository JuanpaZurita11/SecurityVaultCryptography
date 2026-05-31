import { describe, it, expect} from 'vitest';
import { SymmetricEncryption, CipherObject, bytesToB64, b64ToBytes} from '../src/d2.js';
import { randomBytes } from '@noble/ciphers/utils.js';

describe('SignatureCryptoModule Integrity Tests', () => {
  const symmetricModule: SymmetricEncryption = new SymmetricEncryption();

  const message = "Highly sensitive content";
  const rawData = new TextEncoder().encode(message);
  const fileType = "text/plain";


  it('should allow encryption and decrytption', () => {

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
    };

    const {container, symmetricKey} = symmetricModule.encrypt_file(cipherObject);

    const decryptedText = symmetricModule.decrypt_file(container, symmetricKey);


    const data_ = new TextDecoder().decode(decryptedText);

    expect(data_).toEqual(message);
  });

  it('Wrong key fails', () => {

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
    };

    const {container, symmetricKey} = symmetricModule.encrypt_file(cipherObject);

    const wrongKey = randomBytes(32);

    const callDecrypt = () => {
      try {
        return symmetricModule.decrypt_file(container, wrongKey);
      } catch (err) {
        console.log("Error capturado:", (err as Error).message);
        throw err;
      }
    };

    expect(callDecrypt).toThrow();
  });

  it('Modified ciphertext fails', () => {

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
    };

    const {container, symmetricKey} = symmetricModule.encrypt_file(cipherObject);


    // --- MANIPULACIÓN ---
    const data_ = b64ToBytes(container.cipherText_w_tag);
    data_[0] = data_[0] === 0 ? 1 : 0;
    container.cipherText_w_tag = bytesToB64(data_);

    const callDecrypt = () => {
      try {
        return symmetricModule.decrypt_file(container, symmetricKey);
      } catch (err) {
        console.log("Error capturado:", (err as Error).message);
        throw err;
      }
    };

    expect(callDecrypt).toThrow();

  });

  it('Modified metadata fails', () => {

    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
    };

    const {container, symmetricKey} = symmetricModule.encrypt_file(cipherObject);


    // --- MANIPULACIÓN ---
    container.metaData.timestamp = "03/04/2024";

    const callDecrypt = () => {
      try {
        return symmetricModule.decrypt_file(container, symmetricKey);
      } catch (err) {
        console.log("Error capturado:", (err as Error).message);
        throw err;
      }
    };

    expect(callDecrypt).toThrow();

  });

  it('Multiple encryptions produce different cipherText', () => {
    const cipherObject : CipherObject = {
      data: rawData,
      file_type: fileType,
      filename: "secret.txt",
    };

    const encryption1 = symmetricModule.encrypt_file(cipherObject);
    const encryption2 = symmetricModule.encrypt_file(cipherObject);

    const decryption1 = symmetricModule.decrypt_file(encryption1.container, encryption1.symmetricKey);
    const decryption2 = symmetricModule.decrypt_file(encryption2.container, encryption2.symmetricKey);

    const data1 = new TextDecoder().decode(decryption1);
    const data2 = new TextDecoder().decode(decryption2);

    expect(data1).toBe(message);
    expect(data1).toBe(message);

    expect(encryption1.container).not.toEqual(encryption2.container);
  });

});
