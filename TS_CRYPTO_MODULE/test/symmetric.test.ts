import { describe, it, expect, beforeEach } from 'vitest';
import { SymmetricEncryption } from '../src/symmetric_crypto_module'; // Ajusta la ruta

describe('SymmetricEncryption Module', () => {
  let encryptor: SymmetricEncryption;
  const mockFileData = new TextEncoder().encode("Este es un mensaje secreto ultra confidencial 🚀");

  beforeEach(() => {
    encryptor = new SymmetricEncryption();
  });

  // 1. Encrypt -> Decrypt returns identical file
  it('should encrypt and decrypt back to the original content', async () => {
    const { cipherText, metaData, symmetric_key } = await encryptor.encrypt_file(mockFileData);

    const decryptedData = await encryptor.decrypt_file(metaData, cipherText, symmetric_key);

    expect(decryptedData).toEqual(mockFileData);
    expect(new TextDecoder().decode(decryptedData)).toBe("Este es un mensaje secreto ultra confidencial 🚀");
  });

  // 2. Wrong key fails
  it('should fail decryption if the key is incorrect', async () => {
    const { cipherText, metaData } = await encryptor.encrypt_file(mockFileData);
    const wrongKey = String.fromCharCode(...new Uint8Array(32).fill(1)); // Key distinta

    await expect(encryptor.decrypt_file(metaData, cipherText, wrongKey))
      .rejects.toThrow();
  });

  // 3. Modified ciphertext fails (Auth Tag mismatch)
  it('should fail decryption if the ciphertext has been tampered with', async () => {
    const { cipherText, metaData, symmetric_key } = await encryptor.encrypt_file(mockFileData);

    // Modificamos un byte del contenido cifrado
    const corruptedCipher = new Uint8Array(cipherText);
    corruptedCipher[0] === 0 ? corruptedCipher[0] = 1 : corruptedCipher[0] = 0;

    await expect(encryptor.decrypt_file(metaData, corruptedCipher, symmetric_key))
      .rejects.toThrow();
  });

  // 4. Modified metadata fails (AAD mismatch)
  it('should fail decryption if metadata (AAD) is modified', async () => {
    const { cipherText, metaData, symmetric_key } = await encryptor.encrypt_file(mockFileData);

    // Alteramos la metadata (que se usa como Additional Authenticated Data)
    const corruptedMeta = { ...metaData, timestamp: new Date("2010-04-04").toISOString() };

    await expect(encryptor.decrypt_file(corruptedMeta, cipherText, symmetric_key))
      .rejects.toThrow();
  });

  // 5. Multiple encryptions produce different ciphertexts (Non-deterministic)
  it('should produce different ciphertexts for the same input (unique nonces)', async () => {
    const res1 = await encryptor.encrypt_file(mockFileData);
    const res2 = await encryptor.encrypt_file(mockFileData);

    expect(res1.cipherText).not.toEqual(res2.cipherText);
    expect(res1.metaData.nonce).not.toEqual(res2.metaData.nonce);
  });
});