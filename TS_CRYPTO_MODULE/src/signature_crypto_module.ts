import { CipherObject} from "./types";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { equalBytes, randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305, xchacha20 } from '@noble/ciphers/chacha.js';

interface SymmetricMetadata {
  cipher: string;
  key_size_bits: number;
  nonce_size_bytes: number;
  tag_size_bytes: number;
}

interface AsymmetricMetadata {
  scheme: string;
  curve: string;
  kdf: {
    algorithm: string;
    hash: string;
  };
  key_wrapping: {
    cipher: string;
    nonce_size_bytes: 24;
  };
}

interface KeyWrap{
  username: string,
  ephimeralPub: string,
  wrapNonce: string,
  wrappedKey: string
}

interface EncryptionMetadata {
  metaData: {
    file_type: string;
    timestamp: string;
    encryption: string;
    symmetric: SymmetricMetadata;
    asymmetric: AsymmetricMetadata;
  };
  nonce: string;
  recipients: KeyWrap[];

}


export class KeyManager {

  generate_key_pair(): {publicKey: string; privateKey: string}{
    const keyPair = ed25519.keygen();
    const publicKey = btoa(String.fromCharCode(...keyPair.publicKey));
    const privateKey = btoa(String.fromCharCode(...keyPair.secretKey));

    return {publicKey, privateKey};
  }
}

export class SignatureCryptoModule {

  /*
    https://developer.chrome.com/blog/how-to-convert-arraybuffer-to-and-from-string
  */
  str2ab(str: string): ArrayBuffer {
    const buf : ArrayBuffer = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++){
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }


  encrypt_file(cipherObject: CipherObject){

    const symmetric_key = randomBytes(32);
    const nonce = randomBytes(24);

    //ECIES-style
    const recipientsKeyWraps: KeyWrap[]= [];

    for (const recipient of cipherObject.recipients){
      const ephimeralKeyPair = x25519.keygen();
      const ephimeralPriv : Uint8Array = ephimeralKeyPair.secretKey;
      const ephimeralPub : Uint8Array = ephimeralKeyPair.publicKey;

      const pubKey : Uint8Array= new Uint8Array(this.str2ab(atob(recipient.key)));
      const recipientXPub = ed25519.utils.toMontgomery(pubKey);

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
          ephimeralPub: btoa(String.fromCharCode(...ephimeralPub)),
          wrapNonce: btoa(String.fromCharCode(...wrapNonce)),
          wrappedKey: btoa(String.fromCharCode(...xchacha20(derivedKey,wrapNonce,symmetric_key)))
        }
      );
    }

    const metaData : EncryptionMetadata = {
      metaData: {
        file_type: cipherObject.file_type,
        timestamp: new Date().toISOString(),
        encryption: "Hybrid",
        symmetric: {
          cipher: "XChacha20-Poly1305",
          key_size_bits: 256,
          nonce_size_bytes: 24,
          tag_size_bytes: 16
        },
        asymmetric: {
          scheme: "ECIES-style",
          curve: "X25519",
          kdf: {
            algorithm: "HKDF",
            hash: "SHA-256",
          },
          key_wrapping: {
            cipher: "XChaCha20",
            nonce_size_bytes: 24
          }
        }
      },
      nonce: btoa(String.fromCharCode(...nonce)),
      recipients: recipientsKeyWraps
    };

    const aad = new TextEncoder().encode(JSON.stringify(metaData));
    const chacha = xchacha20poly1305(symmetric_key, nonce, aad);
    const cipherText = chacha.encrypt(cipherObject.data);

    return { cipherText, metaData };
  }

  decrypt_file( metaData: EncryptionMetadata, cipherText: Uint8Array, privateKeyBase64: string, recipientKeyWrap: KeyWrap): Uint8Array {

    const privKey : Uint8Array = new Uint8Array(this.str2ab(atob(privateKeyBase64)));
    const recipientXPriv = ed25519.utils.toMontgomerySecret(privKey);

    const ephimeralPub : Uint8Array = new Uint8Array(this.str2ab(atob(recipientKeyWrap.ephimeralPub)));

    const sharedSecret = x25519.getSharedSecret(recipientXPriv,ephimeralPub);

    const derivedKey = hkdf(
      sha256,
      sharedSecret,
      undefined,
      undefined,
      32
    );


    const symmetric_key = xchacha20(derivedKey,new Uint8Array(this.str2ab(atob(recipientKeyWrap.wrapNonce))),new Uint8Array(this.str2ab(atob(recipientKeyWrap.wrappedKey))));

    const nonce = this.str2ab(atob(metaData.nonce));
    const aad = new TextEncoder().encode(JSON.stringify(metaData));

    const chacha = xchacha20poly1305(symmetric_key, new Uint8Array(nonce), aad);
    return chacha.decrypt(cipherText);
  }


  generate_signature(senderPrivateKey: string, senderPublicKey:string, senderUsername:string, cipherObject: CipherObject){
    const {cipherText, metaData} = this.encrypt_file(cipherObject);
    const cipherBase64 = btoa(String.fromCharCode(...cipherText));

    const privKey = new Uint8Array(this.str2ab(atob(senderPrivateKey)));

    const container = {
      ...metaData,
      cipherText: cipherBase64.slice(0, -16),
      tag: cipherBase64.slice(-16)
    };

    const containerDump = new TextEncoder().encode(JSON.stringify(container));
    const signature = ed25519.sign(containerDump, privKey);

    return { ...container, signature: btoa(String.fromCharCode(...signature)),
      signerInfo: {
        username: senderUsername,
        fingerprint: btoa(String.fromCharCode(...sha256(new Uint8Array(this.str2ab(atob(senderPublicKey))))))
      }
    };
  }

  validate_signature(container: any, senderPublicKey: string): boolean{
    const digest = new Uint8Array(this.str2ab(atob(container.signerInfo.fingerprint)));
    const pubKey = new Uint8Array(this.str2ab(atob(senderPublicKey)));
    const derivedFingerprint = sha256(pubKey);

    if (!equalBytes(digest, derivedFingerprint)){
      throw new Error("Error durante el proceso de verificación de firma");
    }

    const msg = {
      metaData: container.metaData,
      nonce: container.nonce,
      recipients: container.recipients,
      cipherText: container.cipherText,
      tag: container.tag
    }

    const msgDump = new TextEncoder().encode(JSON.stringify(msg));
    const signatureBytes = new Uint8Array(this.str2ab(atob(container.signature)));
    if (!ed25519.verify(signatureBytes, msgDump, new Uint8Array(this.str2ab(atob(senderPublicKey))))){
      throw new Error("Error durante el proceso de verificación de firma");
    }
    return true;
  }



}