import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { equalBytes, randomBytes, wrapCipher } from "@noble/ciphers/utils.js";
import { sha256 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305, xchacha20 } from '@noble/ciphers/chacha.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { z } from "zod";
import stringify  from 'fast-json-stable-stringify';



interface SymmetricSpecs {
  cipher: "XChacha20-Poly1305";
  key_size_bits: 256;
  nonce_size_bits: 192;
  tag_size_bits: 128;
}

interface HybridEnc{
  scheme: "ECIES-STYLE";
  asymmetric : {
    curve: "X25519";
    kdf : {
      alg: "HKDF";
      hash: "SHA-256";
      salt: '';
    }
  },
  symmetric:{
    cipher: "XChacha20";
    key_size_bits: 256;
  }
}

interface AAD {

  file_type: string;
  filename: string;
  timestamp: string;

  owner_fingerprint: string;
  ownerWrap: {
    wrapNonce: string;
    wrappedKey: string;
    ephimeral_pub: string;
  }
  encryption: SymmetricSpecs;
  keyWrapping: HybridEnc;
}

export interface KeyWrap{
  username: string;
  wrapNonce: string;
  wrappedKey: string;
  ephimeral_pub: string;
}

export interface EncryptionMetadata extends AAD{
  recipients: KeyWrap[];
  nonce: string;
}

interface Container{
  metaData: EncryptionMetadata;
  cipherText_w_tag: string;
}

export interface SignContainer extends Container{
  signature_algo: "Ed25519";
  signer_id: string;
  signature: string;
}


interface KeyStorageAad{
  metadata: {
    key_type: "Ed25519";
    generated_at: string;
  }
  kdf_parameters:{
    algorithm: "PBKDF2";
    hash: "SHA-256";
    iterations: 524288;
    key_length_bytes: 32;
  };
  privateKey_encryption: {
    algorithm: "XChacha20+Poly1305";
    tag_size_bytes: 16;
  }
  salt: string;
  nonce: string;
  public_key: string;
}

export interface KeyStorage extends KeyStorageAad{
  encryptedPrivateKey_w_tag: string;
}

interface UserInfo {
  username: string;
  publicKey: Uint8Array;
}

export interface CipherObject{
  data : Uint8Array;
  file_type: string;
  filename: string;
  recipients ?: UserInfo[];
}



// ---------------------------------------------------------
// Esquema Completo para SignContainer
// ---------------------------------------------------------
const SignContainerSchema = z.object({
  metaData: z.object({
    file_type: z.string(),
    filename: z.string(),
    timestamp: z.string(),

    owner_fingerprint: z.string(),

    ownerWrap: z.object({
        wrapNonce: z.string(),
        wrappedKey: z.string(),
        ephimeral_pub: z.string(),
    }),

    encryption: z.object({
      cipher: z.string(),
      key_size_bits: z.number(),
      nonce_size_bits: z.number(),
      tag_size_bits: z.number(),
    }),

    keyWrapping: z.object({
      scheme: z.string(),
      asymmetric: z.object({
        curve: z.string(),
        kdf: z.object({
          alg: z.string(),
          hash: z.string(),
          salt: z.string(),
        }),
      }),
      symmetric: z.object({
        cipher: z.string(),
        key_size_bits: z.number(),
      }),
    }),

    recipients: z.array(
      z.object({
        username: z.string(),
        wrapNonce: z.string(),
        wrappedKey: z.string(),
        ephimeral_pub: z.string(),
      })
    ),

    nonce: z.string(),
  }),

  cipherText_w_tag: z.string(),
  signature_algo: z.string(),
  signer_id: z.string(),
  signature: z.string()
});


const KeyStorageSchema = z.object({
  metadata: z.object({
    key_type: z.string(),
    generated_at: z.string(),
  }),
  kdf_parameters: z.object({
    algorithm: z.string(),
    hash: z.string(),
    iterations: z.number(),
    key_length_bytes: z.number(),
  }),
  privateKey_encryption: z.object({
    algorithm: z.string(),
    tag_size_bytes: z.number(),
  }),
  salt: z.string(),
  nonce: z.string(),
  public_key: z.string(),
  encryptedPrivateKey_w_tag: z.string()
});


export function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

export function bytesToB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}


export class CryptoModule {

  generate_key_pair(password: string, expiration_data ?: Date): KeyStorage{
    const keyPair = ed25519.keygen();

    const salt = randomBytes(16);
    const nonce = randomBytes(24);
    const derivedKey = pbkdf2(sha256,password,salt,{ c: 524288, dkLen: 32});

    const aad : KeyStorageAad = {
      metadata: {
        key_type: "Ed25519",
        generated_at: new Date().toDateString()
      },
      kdf_parameters:{
        algorithm: "PBKDF2",
        hash: "SHA-256",
        iterations: 524288,
        key_length_bytes: 32,
      },
      privateKey_encryption: {
        algorithm: "XChacha20+Poly1305",
        tag_size_bytes: 16,
      },
      salt: bytesToB64(salt),
      nonce: bytesToB64(nonce),
      public_key: bytesToB64(keyPair.publicKey)
    };

    const aadDump = new TextEncoder().encode(stringify(aad));

    const chacha = xchacha20poly1305(derivedKey, nonce, aadDump);
    const encrypted_privateKey = chacha.encrypt(keyPair.secretKey);

    return {
      ...aad,
      encryptedPrivateKey_w_tag : bytesToB64(encrypted_privateKey)
    };
  }

  getPrivateKey(secureKeyStorage: KeyStorage, password: string) : Uint8Array{
    const salt = b64ToBytes(secureKeyStorage.salt);
    const nonce = b64ToBytes(secureKeyStorage.nonce);
    const derivedKey = pbkdf2(sha256,password,salt,{c: 524288, dkLen: 32});

    const {encryptedPrivateKey_w_tag, ...aad} = secureKeyStorage;

    const data_ = b64ToBytes(encryptedPrivateKey_w_tag);
    const aadDump = new TextEncoder().encode(stringify(aad));

    const chacha = xchacha20poly1305(derivedKey, nonce, aadDump);
    return chacha.decrypt(data_);
  }

  update_keystorage_password(secureKeyStore: KeyStorage, old_password:string, new_password: string): KeyStorage{

    try{

      const private_key = this.getPrivateKey(secureKeyStore,old_password);

      const salt = randomBytes(16);
      const nonce = randomBytes(24);
      const derivedKey = pbkdf2(sha256,new_password,salt,{c: 524288, dkLen: 32});

      const aad : KeyStorageAad = {
        metadata: {
          key_type: "Ed25519",
          generated_at: new Date().toDateString()
        },
        kdf_parameters:{
          algorithm: "PBKDF2",
          hash: "SHA-256",
          iterations: 524288,
          key_length_bytes: 32,
        },
        privateKey_encryption: {
          algorithm: "XChacha20+Poly1305",
          tag_size_bytes: 16,
        },
        salt: bytesToB64(salt),
        nonce: bytesToB64(nonce),
        public_key: secureKeyStore.public_key
      };

      const aadDump = new TextEncoder().encode(stringify(aad));

      const chacha = xchacha20poly1305(derivedKey, nonce, aadDump);
      const encrypted_privateKey = chacha.encrypt(private_key);

      return {
        ...aad,
        encryptedPrivateKey_w_tag : bytesToB64(encrypted_privateKey)
      };

    }catch(err){
      throw Error("Hubo un problema, no se pudo actualizar la contraseña");
    }
  }

  getPublicKey(secureKeyStorage: KeyStorage): Uint8Array{
    return b64ToBytes(secureKeyStorage.public_key);
  }

  // ----- EXPORT -------
  async serialize_public_key_pem(rawKey: Uint8Array): Promise<string>{
    const spkiObject : CryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      rawKey.buffer as ArrayBuffer,
      "Ed25519",
      true,
      []
    );
    const spkiDer = await globalThis.crypto.subtle.exportKey("spki", spkiObject);

    const exportedAsBase64 = bytesToB64(new Uint8Array(spkiDer));
    return  `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
  }

  // IMPORTAR
  async deserialize_public_key_pem(pem: string): Promise<Uint8Array>{
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';

    if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
      throw new Error('La clave no tiene estructura PEM');
    }

    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length).replace(/\s/g, '');

    const binaryDer = b64ToBytes(pemContents);

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "spki",
      binaryDer.buffer as ArrayBuffer,
      "Ed25519",
      true,
      []
    );

    const rawKey = await globalThis.crypto.subtle.exportKey("raw", cryptoKey);
    return new Uint8Array(rawKey);
  }

  encrypt_file(cipherObject: CipherObject, owner_publicKey: Uint8Array): { cipherText_w_tag: Uint8Array, metaData: EncryptionMetadata } {

    const symmetric_key = randomBytes(32);
    const nonce = randomBytes(24);

    //ECIES-style
    const ephimeralKeyPair = x25519.keygen();
    const ephimeralPriv : Uint8Array = ephimeralKeyPair.secretKey;
    const ephimeralPub : Uint8Array = ephimeralKeyPair.publicKey;
    const ownerXPub = ed25519.utils.toMontgomery(owner_publicKey);
    const sharedSecret = x25519.getSharedSecret(ephimeralPriv,ownerXPub);
    const derivedKey = hkdf(
      sha256,
      sharedSecret,
      undefined,
      undefined,
      32
    );
    const wrapNonce = randomBytes(24);

    const ownerWrap = {
        wrapNonce: bytesToB64(wrapNonce),
        wrappedKey: bytesToB64(xchacha20(derivedKey,wrapNonce,symmetric_key)),
        ephimeral_pub: bytesToB64(ephimeralPub),
    };

    const recipientsKeyWraps : KeyWrap[] = [];

    for (const recipient of cipherObject.recipients ?? []){
      const ephiKeyPair = x25519.keygen();
      const ephiPriv : Uint8Array = ephiKeyPair.secretKey;
      const ephiPub : Uint8Array = ephiKeyPair.publicKey;

      const recipientXPub = ed25519.utils.toMontgomery(recipient.publicKey);

      const secret = x25519.getSharedSecret(ephiPriv,recipientXPub);

      const dKey = hkdf(
        sha256,
        secret,
        undefined,
        undefined,
        32
      );


      const wrapnonce = randomBytes(24);

      recipientsKeyWraps.push(
        {
          username: recipient.username,
          wrapNonce: bytesToB64(wrapnonce),
          wrappedKey: bytesToB64(xchacha20(dKey,wrapnonce,symmetric_key)),
          ephimeral_pub: bytesToB64(ephiPub),
        }
      );
    }

    const specs : AAD = {
      file_type: cipherObject.file_type,
      filename: cipherObject.filename,
      timestamp: new Date().toISOString(),
      owner_fingerprint: bytesToB64(sha256(owner_publicKey)),
      ownerWrap,
      encryption: {
        cipher: "XChacha20-Poly1305",
        key_size_bits: 256,
        nonce_size_bits: 192,
        tag_size_bits: 128,
      },

      keyWrapping:{
        scheme: "ECIES-STYLE",
        asymmetric : {
          curve: "X25519",
          kdf : {
            alg: "HKDF",
            hash: "SHA-256",
            salt: '',
          }
        },
        symmetric:{
          cipher: "XChacha20",
          key_size_bits: 256
        }
      }
    };


    const aad = new TextEncoder().encode(stringify(specs));

    const chacha = xchacha20poly1305(symmetric_key, nonce, aad);
    const cipherText_w_tag = chacha.encrypt(cipherObject.data);

    const metaData : EncryptionMetadata  = {
      ...specs,
      recipients: recipientsKeyWraps,
      nonce: bytesToB64(nonce),
    }

    return { cipherText_w_tag, metaData};
  }

  decrypt_container( container: SignContainer, petitioner_userName: string, petitioner_secureKeyStorage: KeyStorage, password: string, owner_publicKey: Uint8Array): Uint8Array {

    if(!this.validate_container_signature(container,owner_publicKey))throw new Error("Firma no valida");

    const metaData : EncryptionMetadata = container.metaData;

    let petitioner_KeyWrap;
    if (petitioner_userName === container.signer_id) petitioner_KeyWrap = container.metaData.ownerWrap;
    else{
      petitioner_KeyWrap = metaData.recipients.find( (r : KeyWrap) => r.username === petitioner_userName);
    }


    if (!petitioner_KeyWrap) throw new Error("Recipient not found in metadata");


    const petitioner_privateKey = this.getPrivateKey(petitioner_secureKeyStorage,password);

    const petitionerXPriv = ed25519.utils.toMontgomerySecret(petitioner_privateKey);
    const ephimeralPub = b64ToBytes(petitioner_KeyWrap.ephimeral_pub);

    const sharedSecret = x25519.getSharedSecret(petitionerXPriv,ephimeralPub);

    const derivedKey = hkdf(
      sha256,
      sharedSecret,
      undefined,
      undefined,
      32
    );

    const symmetric_key = xchacha20(derivedKey,b64ToBytes(petitioner_KeyWrap.wrapNonce),b64ToBytes(petitioner_KeyWrap.wrappedKey));

    const cipherText_w_tag : Uint8Array = b64ToBytes(container.cipherText_w_tag);
    const nonce = b64ToBytes(metaData.nonce);

    const payload : AAD = {
      file_type: metaData.file_type,
      filename: metaData.filename,
      timestamp: metaData.timestamp,
      owner_fingerprint: metaData.owner_fingerprint,
      ownerWrap: metaData.ownerWrap,
      encryption: metaData.encryption,
      keyWrapping: metaData.keyWrapping
    }

    const aad = new TextEncoder().encode(stringify(payload));

    const chacha = xchacha20poly1305(symmetric_key, nonce, aad);
    return chacha.decrypt(cipherText_w_tag);
  }

  create_container(secureKeyStorage: KeyStorage, password: string, owner_username:string, cipherObject: CipherObject): SignContainer{

    const owner_privateKey : Uint8Array = this.getPrivateKey(secureKeyStorage, password);
    const owner_publicKey : Uint8Array = ed25519.getPublicKey(owner_privateKey);

    const {cipherText_w_tag, metaData} = this.encrypt_file(cipherObject, owner_publicKey);

    const container : Container = {
      metaData,
      cipherText_w_tag: bytesToB64(cipherText_w_tag)
    };

    const payload = {
      ...container,
      signature_algo: "Ed25519",
      signer_id: owner_username
    }

    const payloadDump = new TextEncoder().encode(stringify(payload));
    const signature = bytesToB64(ed25519.sign(payloadDump, owner_privateKey));

    return { ...payload, signature} as SignContainer;
  }

  update_container_recipientKeys(container: SignContainer, owner_secureKeyStorage: KeyStorage, password: string, recipientsUpdate : UserInfo[]): SignContainer{

    const publicKey = b64ToBytes(owner_secureKeyStorage.public_key);
    if(!this.validate_container_signature(container, publicKey))throw new Error("Firma no válida");

    const updatedContainer : SignContainer = structuredClone(container);

    try{

      // Desciframos la llave simétrica
      const privateKey = this.getPrivateKey(owner_secureKeyStorage,password);
      const xPriv = ed25519.utils.toMontgomerySecret(privateKey);
      const ephimeralPub = b64ToBytes(container.metaData.ownerWrap.ephimeral_pub);
      const sharedSecret = x25519.getSharedSecret(xPriv,ephimeralPub);
      const wrapNonce = b64ToBytes(container.metaData.ownerWrap.wrapNonce);

      const derivedKey = hkdf(
        sha256,
        sharedSecret,
        undefined,
        undefined,
        32
      );

      const symmetric_key = xchacha20(derivedKey,wrapNonce,b64ToBytes(container.metaData.ownerWrap.wrappedKey));

      const updatesMap = new Map<string,UserInfo>(recipientsUpdate.map(recipient => [recipient.username,recipient]));

      updatedContainer.metaData.recipients = container.metaData.recipients.map(recipient => {
        const update = updatesMap.get(recipient.username);
        if(update){
          const ephimeralKeyPair = x25519.keygen();
          const ephimeralPriv : Uint8Array = ephimeralKeyPair.secretKey;
          const ephimeralPub : Uint8Array = ephimeralKeyPair.publicKey;
          const recipientXPub = ed25519.utils.toMontgomery(update.publicKey);
          const sharedSecret = x25519.getSharedSecret(ephimeralPriv,recipientXPub);
          const derivedKey = hkdf(
            sha256,
            sharedSecret,
            undefined,
            undefined,
            32
          );
          const wrapNonce = randomBytes(24);

          return {
            username : recipient.username,
            wrapNonce: bytesToB64(wrapNonce),
            wrappedKey : bytesToB64(xchacha20(derivedKey,wrapNonce,symmetric_key)),
            ephimeral_pub : bytesToB64(ephimeralPub)
          }
        }
        return {...recipient};
      });

      const {signature, ...payload} = updatedContainer;
      const payloadDump = new TextEncoder().encode(stringify(payload));
      const sign = bytesToB64(ed25519.sign(payloadDump,privateKey));
      updatedContainer.signature = sign;

    }catch(err){
      throw new Error("No se puedieron actualizar las llaves");
    }
    return updatedContainer;
  }

  add_recipients_to_container(container: SignContainer, owner_secureKeyStorage: KeyStorage, password: string, recipientsInfo: UserInfo[]): SignContainer{

    const publicKey = b64ToBytes(owner_secureKeyStorage.public_key);
    if(!this.validate_container_signature(container, publicKey))throw new Error("Firma no válida");

    const updatedContainer : SignContainer = structuredClone(container);

    try{

      // Desciframos la llave simétrica
      const privateKey = this.getPrivateKey(owner_secureKeyStorage,password);
      const xPriv = ed25519.utils.toMontgomerySecret(privateKey);
      const ephimeralPub = b64ToBytes(container.metaData.ownerWrap.ephimeral_pub);
      const sharedSecret = x25519.getSharedSecret(xPriv,ephimeralPub);
      const wrapNonce = b64ToBytes(container.metaData.ownerWrap.wrapNonce);

      const derivedKey = hkdf(
        sha256,
        sharedSecret,
        undefined,
        undefined,
        32
      );

      const symmetric_key = xchacha20(derivedKey,wrapNonce,b64ToBytes(container.metaData.ownerWrap.wrappedKey));


      const usersInList = new Set<string>(updatedContainer.metaData.recipients.map(recipient => recipient.username));

      for (const newRecipient of recipientsInfo){
        if(!usersInList.has(newRecipient.username)){
          const ephimeralKeyPair = x25519.keygen();
          const ephimeralPriv : Uint8Array = ephimeralKeyPair.secretKey;
          const ephimeralPub : Uint8Array = ephimeralKeyPair.publicKey;
          const recipientXPub = ed25519.utils.toMontgomery(newRecipient.publicKey);
          const sharedSecret = x25519.getSharedSecret(ephimeralPriv,recipientXPub);
          const derivedKey = hkdf(
            sha256,
            sharedSecret,
            undefined,
            undefined,
            32
          );
          const wrapNonce = randomBytes(24);

          updatedContainer.metaData.recipients.push(
            {
            username: newRecipient.username,
            wrapNonce: bytesToB64(wrapNonce),
            wrappedKey: bytesToB64(xchacha20(derivedKey,wrapNonce,symmetric_key)),
            ephimeral_pub: bytesToB64(ephimeralPub)
            }
          );
        }

      }
      const {signature, ...payload} = updatedContainer;
      const payloadDump = new TextEncoder().encode(stringify(payload));
      const sign = bytesToB64(ed25519.sign(payloadDump,privateKey));
      updatedContainer.signature = sign;

    }catch(err){
      throw new Error("No se puedieron actualizar las llaves");
    }
    return updatedContainer;
  }

  remove_recipients_from_container(container: SignContainer, owner_secureKeyStorage: KeyStorage, password:string, usernamesToRemove: string[]){
    const publicKey = b64ToBytes(owner_secureKeyStorage.public_key);
    if(!this.validate_container_signature(container, publicKey))throw new Error("Firma no válida");

    const updatedContainer: SignContainer = structuredClone(container);

    try {
      const privateKey = this.getPrivateKey(owner_secureKeyStorage, password);

      const usersToRemove = new Set<string>(usernamesToRemove);

      updatedContainer.metaData.recipients = updatedContainer.metaData.recipients.filter(
        recipient => !usersToRemove.has(recipient.username)
      );

      const { signature, ...payload } = updatedContainer;
      const payloadDump = new TextEncoder().encode(stringify(payload));
      const sign = bytesToB64(ed25519.sign(payloadDump, privateKey));
      updatedContainer.signature = sign;

    } catch (err) {
      throw new Error("No se pudo remover a los usuarios");
    }

    return updatedContainer;
  }



  validate_container_signature(container: SignContainer, owner_publicKey: Uint8Array): boolean{

    const fingerprint = b64ToBytes(container.metaData.owner_fingerprint);
    const derivedFingerprint = sha256(owner_publicKey);

    if (!equalBytes(fingerprint, derivedFingerprint)) return false;

    const payload = {
      metaData: container.metaData,
      cipherText_w_tag: container.cipherText_w_tag,
      signature_algo: container.signature_algo,
      signer_id: container.signer_id
    }

    const payloadDump = new TextEncoder().encode(stringify(payload));

    const signatureBytes = b64ToBytes(container.signature);

    return ed25519.verify(signatureBytes, payloadDump, owner_publicKey);
  }

  verify_container_structure(container: object): boolean{
    return SignContainerSchema.safeParse(container).success;
  }

  verify_key_container_structure(container: object): boolean{
    return KeyStorageSchema.safeParse(container).success;
  }

}

