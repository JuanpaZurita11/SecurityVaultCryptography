import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { equalBytes, randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305, xchacha20 } from '@noble/ciphers/chacha.js';
import stringify  from 'fast-json-stable-stringify';


interface SymmetricSpecs {
  cipher: "XChacha20-Poly1305";
  key_size_bits: "256",
  nonce_size_bits: "192",
  tag_size_bits: "128"
}

interface HybridEnc{
  scheme: "ECIES-KEM",
  asymmetric : {
    curve: "X25519",
    ephemeral_pub: string,
    kdf : {
      alg: "HKDF",
      hash: "SHA-256"
    }
  },
  symmetric:{
    cipher: "XChacha20",
    key_size_bits: 256
  }
}

interface AAD {

  file_type: string,
  timestamp: string,

  owner_fingerprint: string,

  encryption: SymmetricSpecs,
  keyWrapping: HybridEnc
}

export interface KeyWrap{
  username: string,
  wrapNonce: string,
  wrappedKey: string
}

export interface EncryptionMetadata extends AAD{
  recipients: KeyWrap[],
  nonce: string
}

interface Container{
  metaData: EncryptionMetadata,
  cipherText: string,
}

export interface SignContainer extends Container{
  signer_id: string,
  signature: string
}

interface UserInfo {
  username: string;
  publicKey: Uint8Array;
}

export interface CipherObject{
  data : Uint8Array,
  file_type: string,
  recipients: UserInfo[];
}


export function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

export function bytesToB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}


export class SignatureCryptoModule {

  encrypt_file(cipherObject: CipherObject, owner_fingerprint: string): { cipherText: Uint8Array, metaData: EncryptionMetadata } {

    const symmetric_key = randomBytes(32);
    const nonce = randomBytes(24);

    //ECIES-style
    const ephimeralKeyPair = x25519.keygen();
    const ephimeralPriv : Uint8Array = ephimeralKeyPair.secretKey;
    const ephimeralPub : Uint8Array = ephimeralKeyPair.publicKey;

    const recipientsKeyWraps: KeyWrap[]= [];

    for (const recipient of cipherObject.recipients){

      const recipientXPub = ed25519.utils.toMontgomery(recipient.publicKey);

      const sharedSecret = x25519.getSharedSecret(ephimeralPriv,recipientXPub);

      const derivedKey = hkdf(
        sha256,
        sharedSecret,
        undefined,
        undefined,
        32
      );

      const wrapNonce = randomBytes(24);

      recipientsKeyWraps.push(
        {
          username: recipient.username,
          wrapNonce: bytesToB64(wrapNonce),
          wrappedKey: bytesToB64(xchacha20(derivedKey,wrapNonce,symmetric_key))
        }
      );
    }

    const specs : AAD = {
      file_type: cipherObject.file_type,
      timestamp: new Date().toISOString(),

      owner_fingerprint: owner_fingerprint,

      encryption: {
        cipher: "XChacha20-Poly1305",
        key_size_bits: "256",
        nonce_size_bits: "192",
        tag_size_bits: "128",
      },

      keyWrapping:{
        scheme: "ECIES-KEM",
        asymmetric : {
          curve: "X25519",
          ephemeral_pub: bytesToB64(ephimeralPub),
          kdf : {
            alg: "HKDF",
            hash: "SHA-256"
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
    const cipherText = chacha.encrypt(cipherObject.data);

    const metaData : EncryptionMetadata  = {
      ...specs,
      recipients: recipientsKeyWraps,
      nonce: bytesToB64(nonce),
    }

    return { cipherText , metaData};
  }

  decrypt_file( cipherText: Uint8Array, metaData: EncryptionMetadata, recipientPrivateKey: Uint8Array, recipientKeyWrap: KeyWrap): Uint8Array {

    const recipientXPriv = ed25519.utils.toMontgomerySecret(recipientPrivateKey);
    const ephimeralPub = b64ToBytes(metaData.keyWrapping.asymmetric.ephemeral_pub);

    const sharedSecret = x25519.getSharedSecret(recipientXPriv,ephimeralPub);

    const derivedKey = hkdf(
      sha256,
      sharedSecret,
      undefined,
      undefined,
      32
    );

    const symmetric_key = xchacha20(derivedKey,b64ToBytes(recipientKeyWrap.wrapNonce),b64ToBytes(recipientKeyWrap.wrappedKey));

    const nonce = b64ToBytes(metaData.nonce);

    const payload : AAD = {
      file_type: metaData.file_type,
      timestamp: metaData.timestamp,
      owner_fingerprint: metaData.owner_fingerprint,
      encryption: metaData.encryption,
      keyWrapping: metaData.keyWrapping
    }

    const aad = new TextEncoder().encode(stringify(payload));

    const chacha = xchacha20poly1305(symmetric_key, nonce, aad);
    return chacha.decrypt(cipherText);
  }

  create_container(owner_privateKey: Uint8Array, owner_publicKey: Uint8Array, owner_username:string, cipherObject: CipherObject): SignContainer{
    const {cipherText, metaData} = this.encrypt_file(cipherObject, bytesToB64(sha256(owner_publicKey)));

    const container : Container = {
      metaData,
      cipherText: bytesToB64(cipherText)
    };

    const payload = {
      ...container,
      signer_id: owner_username
    }

    const payloadDump = new TextEncoder().encode(stringify(payload));
    const signature = ed25519.sign(payloadDump, owner_privateKey);

    return { ...payload, signature: bytesToB64(signature) };
  }

  verify_container(container: SignContainer, owner_publicKey: Uint8Array): boolean{

    const fingerprint = b64ToBytes(container.metaData.owner_fingerprint);
    const derivedFingerprint = sha256(owner_publicKey);

    if (!equalBytes(fingerprint, derivedFingerprint)) return false;

    const payload = {
      metaData: container.metaData,
      cipherText: container.cipherText,
      signer_id: container.signer_id
    }

    const payloadDump = new TextEncoder().encode(stringify(payload));

    const signatureBytes = b64ToBytes(container.signature);

    return ed25519.verify(signatureBytes, payloadDump, owner_publicKey);
  }
}

