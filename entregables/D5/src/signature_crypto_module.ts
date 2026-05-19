/**
 * @fileoverview D5 — Módulo de Firma Digital y Cifrado Híbrido ECIES-style
 *
 * Implementa cifrado híbrido usando ECIES-style sobre Curve25519 (X25519 + HKDF)
 * para la distribución de llaves, y firmas digitales Ed25519 para autenticidad de origen.
 *
 * **Diferencia clave respecto a D3:**
 * D3 usa RSA-OAEP (Web Crypto) para envolver la llave simétrica. D5 usa
 * **ECIES-style sobre Curve25519**, lo que permite derivar las llaves de
 * encriptación directamente desde las mismas llaves Ed25519 de firma
 * (via `toMontgomery`), eliminando la necesidad de gestionar dos pares de llaves.
 *
 * **Esquema ECIES-style:**
 * ```
 * Para cada destinatario:
 *   1. Generar par efímero X25519 (ephimeral keypair)
 *   2. ECDH: sharedSecret = X25519(ephimeralPriv, recipientXPub)
 *      donde recipientXPub = ed25519.toMontgomery(recipient.publicKey)
 *   3. Derivar llave de wrap: HKDF-SHA256(sharedSecret, 32 bytes)
 *   4. Envolver: wrappedKey = XChaCha20(derivedKey, wrapNonce, symmetric_key)
 *   5. Almacenar: ephimeralPub (pública efímera para que el receptor haga ECDH inverso)
 * ```
 *
 * **Flujo de firma:**
 * ```
 * create_container():
 *   payload = { metaData, cipherText_w_tag, signature_algo, signer_id }
 *   signature = Ed25519.sign(stringify(payload), owner_privateKey)
 *   return { ...payload, signature }
 * ```
 *
 * **Canonicalización:**
 * Todos los payloads se serializan con `fast-json-stable-stringify` antes de
 * firmar o usar como AAD, garantizando bytes deterministas independientemente
 * del orden de construcción del objeto.
 *
 * @module signature_crypto_module
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { equalBytes, randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305, xchacha20 } from "@noble/ciphers/chacha.js";
import stringify from "fast-json-stable-stringify";

// Interfaces internas

/**
 * Parámetros del cifrado simétrico XChaCha20-Poly1305, incluidos en el AAD.
 * @interface SymmetricSpecs
 * @internal
 */
interface SymmetricSpecs {
	cipher: "XChacha20-Poly1305";
	key_size_bits: 256;
	nonce_size_bits: 192;
	tag_size_bits: 128;
}

/**
 * Parámetros del esquema de encapsulación de llave (ECIES-style), incluidos en el AAD.
 * @interface HybridEnc
 * @internal
 */
interface HybridEnc {
	scheme: "ECIES-STYLE";
	asymmetric: {
		curve: "X25519";
		kdf: {
			alg: "HKDF";
			hash: "SHA-256";
		};
	};
	symmetric: {
		cipher: "XChacha20";
		key_size_bits: 256;
	};
}

/**
 * Datos que actúan como AAD en el cifrado XChaCha20-Poly1305.
 *
 * Nota crítica: `AAD` excluye `recipients` y `nonce` a propósito.
 * Solo los campos estables del archivo y la llave efímera compartida
 * forman el AAD, mientras que `recipients` y `nonce` se añaden a
 * `EncryptionMetadata` pero no afectan la autenticación del ciphertext.
 *
 * @interface AAD
 * @internal
 */
interface AAD {
	file_type: string;
	filename: string;
	/** Timestamp ISO-8601 del momento del cifrado. */
	timestamp: string;
	/**
	 * SHA-256 de la llave pública Ed25519 del propietario en Base64.
	 * Vincula el contenedor con su creador de forma verificable.
	 */
	owner_fingerprint: string;
	/** Llave pública efímera X25519 en Base64. Usada por los destinatarios para ECDH. */
	container_key: string;
	encryption: SymmetricSpecs;
	keyWrapping: HybridEnc;
}

// Interfaces exportadas

/**
 * Datos de la llave simétrica envuelta para un destinatario específico.
 *
 * Para descifrar, el receptor realiza:
 * ```
 * recipientXPriv = toMontgomerySecret(recipient_privateKey)
 * sharedSecret   = X25519(recipientXPriv, container_key_bytes)
 * derivedKey     = HKDF-SHA256(sharedSecret, 32)
 * symmetric_key  = XChaCha20(derivedKey, wrapNonce, wrappedKey)
 * ```
 *
 * @interface KeyWrap
 */
export interface KeyWrap {
	/** Nombre de usuario del destinatario. */
	username: string;
	/** Nonce de 192 bits usado para envolver la llave, en Base64. */
	wrapNonce: string;
	/** Llave simétrica envuelta con XChaCha20, en Base64. */
	wrappedKey: string;
}

/**
 * Metadatos completos del contenedor cifrado, incluyendo lista de destinatarios.
 *
 * Extiende {@link AAD} añadiendo los campos que varían por cifrado:
 * la lista de destinatarios y el nonce del ciphertext principal.
 *
 * @interface EncryptionMetadata
 */
export interface EncryptionMetadata extends AAD {
	/** Lista de destinatarios con sus llaves simétricas envueltas. */
	recipients: KeyWrap[];
	/** Nonce de 192 bits del cifrado principal XChaCha20-Poly1305, en Base64. */
	nonce: string;
}

/**
 * Contenedor firmado que incluye ciphertext, metadatos y firma Ed25519.
 *
 * La firma cubre: `{ metaData, cipherText_w_tag, signature_algo, signer_id }`,
 * lo que vincula criptográficamente el contenido, los metadatos, el algoritmo
 * y la identidad del firmante. Cualquier modificación a estos campos invalida la firma.
 *
 * @interface SignContainer
 */
export interface SignContainer {
	metaData: EncryptionMetadata;
	/**
	 * Ciphertext + tag Poly1305 en Base64.
	 * Los últimos 16 bytes son el authentication tag.
	 */
	cipherText_w_tag: string;
	/** Algoritmo de firma usado. */
	signature_algo: "Ed25519";
	/** Nombre de usuario del propietario/firmante. */
	signer_id: string;
	/** Firma Ed25519 en Base64 sobre el payload canónico del contenedor. */
	signature: string;
}

/**
 * Datos de entrada para cifrar un archivo en D5.
 * @interface CipherObject
 */
export interface CipherObject {
	/** Contenido del archivo en bytes. */
	data: Uint8Array;
	/** Tipo MIME del archivo. */
	file_type: string;
	/** Nombre del archivo. */
	filename: string;
	/** Lista de destinatarios (nombre + llave pública Ed25519 raw). */
	recipients: Array<{ username: string; publicKey: Uint8Array }>;
}

// Utilidades

/**
 * Decodifica Base64 a bytes.
 * @param b64 - Cadena Base64.
 * @returns Bytes decodificados.
 */
export function b64ToBytes(b64: string): Uint8Array {
	return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Codifica bytes a Base64.
 * @param bytes - Bytes a codificar.
 * @returns Cadena Base64.
 */
export function bytesToB64(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes));
}

// Clase principal

/**
 * Módulo central de D5: cifrado híbrido ECIES-style + firma Ed25519.
 *
 * Combina tres capas de seguridad:
 * 1. **Confidencialidad:** XChaCha20-Poly1305 AEAD para el ciphertext.
 * 2. **Control de acceso:** ECIES-style X25519/HKDF para distribución de llaves.
 * 3. **Autenticidad:** Ed25519 para firma digital del contenedor completo.
 *
 * @class SignatureCryptoModule
 */
export class SignatureCryptoModule {
	/**
	 * Cifra un archivo para múltiples destinatarios usando ECIES-style.
	 *
	 * A diferencia de D3 (RSA-OAEP), aquí se usa un **par efímero X25519** compartido
	 * para todos los destinatarios. Cada destinatario recibe su propia `wrappedKey`
	 * derivada del ECDH entre la llave efímera y su llave pública convertida a Montgomery.
	 *
	 * **Importante:** Este método es llamado internamente por {@link create_container}.
	 * El `owner_fingerprint` (SHA-256 de la llave pública del propietario) se incluye
	 * en el AAD, vinculando el ciphertext con la identidad del creador antes de firmar.
	 *
	 * @param cipherObject - Archivo y destinatarios a cifrar.
	 * @param owner_fingerprint - SHA-256(owner_publicKey) en Base64, incluido en AAD.
	 * @returns Ciphertext con tag Poly1305 y metadatos listos para empaquetar.
	 *
	 * @internal Usar {@link create_container} para el flujo completo con firma.
	 */
	encrypt_file(
		cipherObject: CipherObject,
		owner_fingerprint: string,
	): { cipherText_w_tag: Uint8Array; metaData: EncryptionMetadata } {
		const symmetric_key = randomBytes(32);
		const nonce = randomBytes(24);

		const ephimeralKeyPair = x25519.keygen();
		const ephimeralPriv = ephimeralKeyPair.secretKey;
		const ephimeralPub = ephimeralKeyPair.publicKey;

		const recipientsKeyWraps: KeyWrap[] = [];

		for (const recipient of cipherObject.recipients) {
			const recipientXPub = ed25519.utils.toMontgomery(
				recipient.publicKey,
			);
			const sharedSecret = x25519.getSharedSecret(
				ephimeralPriv,
				recipientXPub,
			);
			const derivedKey = hkdf(
				sha256,
				sharedSecret,
				undefined,
				undefined,
				32,
			);
			const wrapNonce = randomBytes(24);
			recipientsKeyWraps.push({
				username: recipient.username,
				wrapNonce: bytesToB64(wrapNonce),
				wrappedKey: bytesToB64(
					xchacha20(derivedKey, wrapNonce, symmetric_key),
				),
			});
		}

		const specs: AAD = {
			file_type: cipherObject.file_type,
			filename: cipherObject.filename,
			timestamp: new Date().toISOString(),
			owner_fingerprint,
			encryption: {
				cipher: "XChacha20-Poly1305",
				key_size_bits: 256,
				nonce_size_bits: 192,
				tag_size_bits: 128,
			},
			keyWrapping: {
				scheme: "ECIES-STYLE",
				asymmetric: {
					curve: "X25519",
					kdf: { alg: "HKDF", hash: "SHA-256" },
				},
				symmetric: { cipher: "XChacha20", key_size_bits: 256 },
			},
			container_key: bytesToB64(ephimeralPub),
		};

		const aad = new TextEncoder().encode(stringify(specs));
		const chacha = xchacha20poly1305(symmetric_key, nonce, aad);
		const cipherText_w_tag = chacha.encrypt(cipherObject.data);

		const metaData: EncryptionMetadata = {
			...specs,
			recipients: recipientsKeyWraps,
			nonce: bytesToB64(nonce),
		};
		return { cipherText_w_tag, metaData };
	}

	/**
	 * Descifra un contenedor firmado para un destinatario específico.
	 *
	 * **Flujo completo:**
	 * 1. Valida la firma Ed25519 del contenedor con {@link validate_container}.
	 * 2. Busca la entrada del destinatario en `metaData.recipients`.
	 * 3. Convierte la llave privada Ed25519 a X25519 (`toMontgomerySecret`).
	 * 4. ECDH con la llave efímera pública → HKDF → llave de unwrap.
	 * 5. XChaCha20 unwrap → llave simétrica.
	 * 6. XChaCha20-Poly1305 decrypt → plaintext.
	 *
	 * @param container - Contenedor firmado producido por {@link create_container}.
	 * @param recipient_userName - Nombre del destinatario que quiere descifrar.
	 * @param recipient_privateKey - Llave privada Ed25519 raw (32 bytes) del destinatario.
	 * @param owner_publicKey - Llave pública Ed25519 raw del firmante, para verificar firma.
	 * @returns Plaintext del archivo en bytes.
	 *
	 * @throws Error `"Firma no valida"` si la firma Ed25519 no verifica.
	 * @throws Error `"Recipient not found in metadata"` si el usuario no está autorizado.
	 * @throws Error criptográfico si los metadatos o ciphertext fueron modificados.
	 */
	decrypt_container(
		container: SignContainer,
		recipient_userName: string,
		recipient_privateKey: Uint8Array,
		owner_publicKey: Uint8Array,
	): Uint8Array {
		if (!this.validate_container(container, owner_publicKey))
			throw new Error("Firma no valida");

		const metaData = container.metaData;
		const cipherText_w_tag = b64ToBytes(container.cipherText_w_tag);

		const recipientKeyWrap = metaData.recipients.find(
			(r) => r.username === recipient_userName,
		);
		if (!recipientKeyWrap)
			throw new Error("Recipient not found in metadata");

		const recipientXPriv =
			ed25519.utils.toMontgomerySecret(recipient_privateKey);
		const ephimeralPub = b64ToBytes(metaData.container_key);
		const sharedSecret = x25519.getSharedSecret(
			recipientXPriv,
			ephimeralPub,
		);
		const derivedKey = hkdf(sha256, sharedSecret, undefined, undefined, 32);
		const symmetric_key = xchacha20(
			derivedKey,
			b64ToBytes(recipientKeyWrap.wrapNonce),
			b64ToBytes(recipientKeyWrap.wrappedKey),
		);
		const nonce = b64ToBytes(metaData.nonce);

		const payload: AAD = {
			file_type: metaData.file_type,
			filename: metaData.filename,
			timestamp: metaData.timestamp,
			owner_fingerprint: metaData.owner_fingerprint,
			encryption: metaData.encryption,
			keyWrapping: metaData.keyWrapping,
			container_key: metaData.container_key,
		};

		const aad = new TextEncoder().encode(stringify(payload));
		const chacha = xchacha20poly1305(symmetric_key, nonce, aad);
		return chacha.decrypt(cipherText_w_tag);
	}

	/**
	 * Crea y firma un contenedor cifrado completo.
	 *
	 * Combina {@link encrypt_file} y la firma Ed25519 en un único paso.
	 * El `owner_fingerprint` (SHA-256 de la llave pública del propietario)
	 * se incluye en el AAD del ciphertext **y** en el payload firmado,
	 * vinculando criptográficamente la identidad del creador con el contenido.
	 *
	 * **Payload que se firma (canonicalizado con `fast-json-stable-stringify`):**
	 * ```ts
	 * { metaData, cipherText_w_tag, signature_algo: "Ed25519", signer_id }
	 * ```
	 *
	 * @param owner_privateKey - Llave privada Ed25519 del propietario (32 bytes).
	 * @param owner_publicKey - Llave pública Ed25519 del propietario (32 bytes).
	 * @param owner_username - Nombre de usuario del propietario, almacenado en `signer_id`.
	 * @param cipherObject - Archivo y destinatarios a cifrar.
	 * @returns {@link SignContainer} con ciphertext firmado y metadatos completos.
	 *
	 * @example
	 * ```ts
	 * const scm = new SignatureCryptoModule();
	 * const container = scm.create_container(
	 *   ownerPrivKey, ownerPubKey, "juan",
	 *   { data, file_type, filename, recipients: [...] }
	 * );
	 * // container.signature: firma Ed25519 en Base64
	 * // container.signer_id: "juan"
	 * ```
	 */
	create_container(
		owner_privateKey: Uint8Array,
		owner_publicKey: Uint8Array,
		owner_username: string,
		cipherObject: CipherObject,
	): SignContainer {
		const { cipherText_w_tag, metaData } = this.encrypt_file(
			cipherObject,
			bytesToB64(sha256(owner_publicKey)),
		);
		const container = {
			metaData,
			cipherText_w_tag: bytesToB64(cipherText_w_tag),
		};
		const payload = {
			...container,
			signature_algo: "Ed25519",
			signer_id: owner_username,
		};
		const payloadDump = new TextEncoder().encode(stringify(payload));
		const signature = ed25519.sign(payloadDump, owner_privateKey);
		return {
			...payload,
			signature: bytesToB64(signature),
		} as SignContainer;
	}

	/**
	 * Método pendiente de implementación para verificación de estructura del contenedor.
	 *
	 * @param container - Objeto a verificar.
	 * @todo Implementar validación de esquema. Ver {@link validate_container} para
	 *   la verificación criptográfica de la firma.
	 * @deprecated No implementado en D5; en D6 se usa Zod para validación de esquema.
	 */
	verify_container(_container: object): void {
		// Pendiente de implementación
	}

	/**
	 * Verifica criptográficamente la firma Ed25519 de un contenedor.
	 *
	 * **Pasos de verificación:**
	 * 1. Decodifica el `owner_fingerprint` almacenado en los metadatos.
	 * 2. Calcula SHA-256 de la `owner_publicKey` provista.
	 * 3. Compara ambos con `equalBytes` — si no coinciden, retorna `false`
	 *    (la llave pública no corresponde al creador del contenedor).
	 * 4. Reconstruye el payload canónico: `{ metaData, cipherText_w_tag, signature_algo, signer_id }`.
	 * 5. Verifica la firma Ed25519 sobre el payload serializado con `fast-json-stable-stringify`.
	 *
	 * @param container - Contenedor firmado a verificar.
	 * @param owner_publicKey - Llave pública Ed25519 raw del firmante esperado.
	 * @returns `true` si el fingerprint coincide y la firma es válida; `false` en caso contrario.
	 *
	 * @remarks
	 * Este método es llamado internamente por {@link decrypt_container} antes de descifrar.
	 * Un retorno `false` implica que el contenedor fue modificado o que la llave pública
	 * no corresponde al creador. En ambos casos el descifrado no procede.
	 */
	validate_container(
		container: SignContainer,
		owner_publicKey: Uint8Array,
	): boolean {
		const fingerprint = b64ToBytes(container.metaData.owner_fingerprint);
		const derivedFingerprint = sha256(owner_publicKey);
		if (!equalBytes(fingerprint, derivedFingerprint)) return false;

		const payload = {
			metaData: container.metaData,
			cipherText_w_tag: container.cipherText_w_tag,
			signature_algo: container.signature_algo,
			signer_id: container.signer_id,
		};
		const payloadDump = new TextEncoder().encode(stringify(payload));
		const signatureBytes = b64ToBytes(container.signature);
		return ed25519.verify(signatureBytes, payloadDump, owner_publicKey);
	}
}
