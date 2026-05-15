import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { equalBytes, randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305, xchacha20 } from '@noble/ciphers/chacha.js';
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

  encryption: SymmetricSpecs;
  keyWrapping: HybridEnc;
  container_key: string;
}

export interface KeyWrap{
  username: string;
  wrapNonce: string;
  wrappedKey: string;

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

interface UserInfo {
  username: string;
  publicKey: Uint8Array;
}

export interface CipherObject{
  data : Uint8Array;
  file_type: string;
  filename: string;
  recipients: UserInfo[];
}


export function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

export function bytesToB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}


export class SignatureCryptoModule {

  encrypt_file(cipherObject: CipherObject, owner_fingerprint: string): { cipherText_w_tag: Uint8Array, metaData: EncryptionMetadata } {

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
      filename: cipherObject.filename,
      timestamp: new Date().toISOString(),
      owner_fingerprint: owner_fingerprint,

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
            hash: "SHA-256"
          }
        },
        symmetric:{
          cipher: "XChacha20",
          key_size_bits: 256
        }
      },
      container_key: bytesToB64(ephimeralPub)
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

  decrypt_container( container: SignContainer, recipient_userName: string, recipient_privateKey: Uint8Array, owner_publicKey: Uint8Array): Uint8Array {

    if(!this.validate_container(container,owner_publicKey))throw new Error("Firma no valida");


    const metaData : EncryptionMetadata = container.metaData;
    const cipherText_w_tag : Uint8Array = b64ToBytes(container.cipherText_w_tag);

    const recipientKeyWrap : KeyWrap | undefined = metaData.recipients.find( (r : KeyWrap) => r.username === recipient_userName);
    if (!recipientKeyWrap) throw new Error("Recipient not found in metadata");


    const recipientXPriv = ed25519.utils.toMontgomerySecret(recipient_privateKey);
    const ephimeralPub = b64ToBytes(metaData.container_key);

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
      filename: metaData.filename,
      timestamp: metaData.timestamp,
      owner_fingerprint: metaData.owner_fingerprint,
      encryption: metaData.encryption,
      keyWrapping: metaData.keyWrapping,
      container_key: metaData.container_key
    }

    const aad = new TextEncoder().encode(stringify(payload));

    const chacha = xchacha20poly1305(symmetric_key, nonce, aad);
    return chacha.decrypt(cipherText_w_tag);
  }

  create_container(owner_privateKey: Uint8Array, owner_publicKey: Uint8Array, owner_username:string, cipherObject: CipherObject): SignContainer{
    const {cipherText_w_tag, metaData} = this.encrypt_file(cipherObject, bytesToB64(sha256(owner_publicKey)));

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
    const signature = ed25519.sign(payloadDump, owner_privateKey);

    return { ...payload, signature: bytesToB64(signature) } as SignContainer;
  }

  verify_container(container: object){


  }

  validate_container(container: SignContainer, owner_publicKey: Uint8Array): boolean{

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

}

