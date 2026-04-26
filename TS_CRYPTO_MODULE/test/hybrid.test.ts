
import { describe, it, expect, beforeEach } from 'vitest';
import { KeyManager, HybridEncryption } from '../src/hybrid_crypto_module';

describe('HybridEncryption Module Tests', () => {
  let keyManager: KeyManager;
  let hybridEnc: HybridEncryption;

  // Test Data
  const rawData = new TextEncoder().encode("Top Secret Data");
  const fileType = "text/plain";

  beforeEach(() => {
    keyManager = new KeyManager();
    hybridEnc = new HybridEncryption();
  });

  it('should allow two different recipients to decrypt the same file', async () => {
    const ownerKeys = await keyManager.generate_key_pair();
    const user1Keys = await keyManager.generate_key_pair();
    const user2Keys = await keyManager.generate_key_pair();

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      ownerKey: ownerKeys.publicKey,
      recipients: [
        { username: 'Alice', key: user1Keys.publicKey },
        { username: 'Bob', key: user2Keys.publicKey }
      ]
    };

    const { cipherText, metaData } = await hybridEnc.encrypt_file(cipherObject);

    // User 1 Decrypts
    const decrypted1 = await hybridEnc.decrypt_file(
      metaData,
      cipherText,
      user1Keys.privateKey,
      metaData.recipients[0].key
    );


    // User 2 Decrypts
    const decrypted2 = await hybridEnc.decrypt_file(
      metaData,
      cipherText,
      user2Keys.privateKey,
      metaData.recipients[1].key
    );

    expect(new TextDecoder().decode(decrypted1)).toBe("Top Secret Data");
    expect(new TextDecoder().decode(decrypted2)).toBe("Top Secret Data");
  });

  it('should fail when an unauthorized user attempts to decrypt', async () => {
    const ownerKeys = await keyManager.generate_key_pair();
    const unauthorizedKeys = await keyManager.generate_key_pair();

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      ownerKey: ownerKeys.publicKey,
      recipients: [{username: "owner", key: ownerKeys.publicKey }]
    };

    const { cipherText, metaData } = await hybridEnc.encrypt_file(cipherObject);

    // Attempting to decrypt using a key that wasn't included in the recipients
    await expect(
      hybridEnc.decrypt_file(metaData, cipherText, unauthorizedKeys.privateKey, metaData.recipients[0].key)
    ).rejects.toThrow();
  });

  it('should fail if the metadata (AAD) is tampered with', async () => {
    const ownerKeys = await keyManager.generate_key_pair();
    const user1Keys = await keyManager.generate_key_pair();

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      ownerKey: ownerKeys.publicKey,
      recipients: [{username: 'Alice', key: user1Keys.publicKey }]
    };

    const { cipherText, metaData } = await hybridEnc.encrypt_file(cipherObject);

    // Tamper with metadata: Add a fake recipient entry
    const tamperedMetaData = { ...metaData };
    tamperedMetaData.recipients = [...metaData.recipients, {username:'Alice', key: "fake-key" }];

    // Decryption should fail because the AAD (Additional Authenticated Data) won't match the Poly1305 tag
    await expect(
      hybridEnc.decrypt_file(tamperedMetaData, cipherText, user1Keys.privateKey, metaData.recipients[0].key)
    ).rejects.toThrow();
  });


  it('should fail when the correct recipient uses the wrong private key', async () => {
    const ownerKeys = await keyManager.generate_key_pair();
    const user1Keys = await keyManager.generate_key_pair();
    const user2Keys = await keyManager.generate_key_pair(); // Different keypair

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      ownerKey: ownerKeys.publicKey,
      recipients: [{username:'Bob', key: user1Keys.publicKey }]
    };

    const { cipherText, metaData } = await hybridEnc.encrypt_file(cipherObject);

    // User 1 tries to use User 2's private key to decrypt User 1's encrypted symmetric key
    await expect(
      hybridEnc.decrypt_file(metaData, cipherText, user2Keys.privateKey, metaData.recipients[0].key)
    ).rejects.toThrow();
  });

  it('should fail if a recipient entry is removed from metadata', async () => {
    const ownerKeys = await keyManager.generate_key_pair();
    const user1Keys = await keyManager.generate_key_pair();

    const cipherObject = {
      data: rawData,
      file_type: fileType,
      ownerKey: ownerKeys.publicKey,
      recipients: [{ username: 'Bob', key: user1Keys.publicKey }]
    };

    const { cipherText, metaData } = await hybridEnc.encrypt_file(cipherObject);

    // Remove the recipient from the metadata
    const brokenMetaData = { ...metaData };
    brokenMetaData.recipients = [];

    // Even if we have the correct private key, the Poly1305 authentication will fail
    // because the JSON.stringify(metaData) used as AAD has changed.
    await expect(
      hybridEnc.decrypt_file(brokenMetaData, cipherText, user1Keys.privateKey, metaData.recipients[0].key)
    ).rejects.toThrow();
  });
});
