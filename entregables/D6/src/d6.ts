/**
 * @fileoverview D6 — CryptoModule: Gestión Segura de Llaves y Cifrado Completo
 *
 * Módulo central del sistema que integra todas las capas previas (D1-D5) en
 * una sola clase (`CryptoModule`) con gestión segura de llaves privadas.
 *
 * **Principales diferencias respecto a D5 (`SignatureCryptoModule`):**
 *
 * 1. **Llaves protegidas por contraseña:** La llave privada nunca se expone en
 *    texto plano fuera de la clase. Se almacena cifrada en un `KeyStorage` usando
 *    PBKDF2-SHA256 + XChaCha20-Poly1305. El usuario solo provee su contraseña
 *    en cada operación; la llave se descifra en memoria para esa operación y se descarta.
 *
 * 2. **ownerWrap separado:** En D5, la llave efímera era compartida para todos los
 *    destinatarios. En D6, el propietario (`owner`) tiene su propio `ownerWrap`
 *    (par efímero independiente), separado de los `recipients`. Esto permite al
 *    propietario descifrar su propio archivo usando `petitioner_userName === signer_id`,
 *    sin necesitar una entrada en la lista de destinatarios.
 *
 * 3. **Gestión del ciclo de vida del contenedor:** Funciones para añadir/quitar/actualizar
 *    destinatarios sin re-cifrar el archivo, re-firmando el contenedor tras cada cambio.
 *
 * 4. **Validación de esquema con Zod:** `verify_container_structure` y
 *    `verify_key_container_structure` validan la estructura del JSON usando esquemas Zod,
 *    complementando la verificación criptográfica de `validate_container_signature`.
 *
 * **KDF — Por qué PBKDF2 con 524,288 iteraciones:**
 * PBKDF2-SHA256 es el KDF disponible de forma nativa en entornos browser/Node.js a través
 * de `@noble/hashes`. Con 2^19 = 524,288 iteraciones, cada intento de brute-force
 * tarda ~500ms en hardware moderno, haciendo los ataques offline inviables para
 * contraseñas con entropía razonable.
 *
 * **Canonicalización:**
 * Todos los payloads (AAD, firma, KeyStorage) se serializan con `fast-json-stable-stringify`
 * (llaves en orden determinista), garantizando que el mismo objeto siempre produzca
 * los mismos bytes independientemente del orden de construcción.
 *
 * @module d6
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { equalBytes, randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305, xchacha20 } from "@noble/ciphers/chacha.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { z } from "zod";
import stringify from "fast-json-stable-stringify";

// Interfaces de cifrado de archivo

/**
 * Parámetros técnicos del cifrado simétrico XChaCha20-Poly1305.
 * Se incluyen en el AAD del ciphertext.
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
 * Parámetros del esquema ECIES-style usado para encapsular la llave simétrica.
 * Se incluyen en el AAD del ciphertext.
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
			salt: "";
		};
	};
	symmetric: {
		cipher: "XChacha20";
		key_size_bits: 256;
	};
}

/**
 * Datos que se usan como AAD en el cifrado principal XChaCha20-Poly1305.
 *
 * Contiene toda la información de contexto del archivo y del propietario.
 * `recipients` y `nonce` se añaden en `EncryptionMetadata` pero no forman
 * parte del AAD, de modo que el propietario puede gestionar la lista de
 * destinatarios sin invalidar el tag del ciphertext.
 *
 * @interface AAD
 * @internal
 */
interface AAD {
	/** Tipo MIME del archivo. */
	file_type: string;
	/** Nombre del archivo. */
	filename: string;
	/** Timestamp ISO-8601 del momento del cifrado. */
	timestamp: string;
	/**
	 * SHA-256 de la llave pública Ed25519 del propietario, en Base64.
	 * Vincula el ciphertext con la identidad del creador de forma verificable.
	 */
	owner_fingerprint: string;
	/**
	 * Llave simétrica envuelta exclusivamente para el propietario.
	 * Usa un par efímero X25519 independiente al de los destinatarios,
	 * garantizando que el propietario siempre pueda descifrar su propio archivo.
	 */
	ownerWrap: {
		/** Nonce de 192 bits del XChaCha20 de wrap, en Base64. */
		wrapNonce: string;
		/** Llave simétrica envuelta con XChaCha20, en Base64. */
		wrappedKey: string;
		/** Llave pública efímera X25519 para que el propietario haga ECDH, en Base64. */
		ephimeral_pub: string;
	};
	encryption: SymmetricSpecs;
	keyWrapping: HybridEnc;
}

// Interfaces exportadas de cifrado

/**
 * Datos de la llave simétrica envuelta para un destinatario.
 *
 * A diferencia de D5, cada `KeyWrap` en D6 tiene su propio `ephimeral_pub`
 * (par efímero independiente por destinatario), maximizando el forward secrecy.
 *
 * @interface KeyWrap
 */
interface KeyWrap {
	/** Nombre del destinatario, usado como identificador durante el descifrado. */
	username: string;
	/** Nonce de 192 bits del XChaCha20 de wrap, en Base64. */
	wrapNonce: string;
	/** Llave simétrica envuelta con XChaCha20, en Base64. */
	wrappedKey: string;
	/** Llave pública efímera X25519 del destinatario para ECDH, en Base64. */
	ephimeral_pub: string;
}

/**
 * Metadatos completos del contenedor, incluyendo destinatarios y nonce.
 *
 * Extiende {@link AAD} con los campos variables por cifrado.
 * La lista `recipients` puede ser modificada por el propietario sin
 * invalidar el tag del ciphertext, siempre que se re-firme el contenedor.
 *
 * @interface EncryptionMetadata
 */
export interface EncryptionMetadata extends AAD {
	/** Lista de destinatarios adicionales con sus llaves envueltas. */
	recipients: KeyWrap[];
	/** Nonce de 192 bits del cifrado principal XChaCha20-Poly1305, en Base64. */
	nonce: string;
}

/**
 * Contenedor cifrado y firmado.
 *
 * La firma cubre: `{ metaData, cipherText_w_tag, signature_algo, signer_id }`,
 * vinculando criptográficamente el ciphertext, los metadatos (con `ownerWrap` y
 * la lista de `recipients`), el algoritmo de firma y la identidad del creador.
 *
 * @interface SignContainer
 */
export interface SignContainer {
	/** Metadatos completos del cifrado. */
	metaData: EncryptionMetadata;
	/**
	 * Ciphertext + tag Poly1305 concatenados en Base64.
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

// Interfaces de almacenamiento seguro de llave

/**
 * Parte del `KeyStorage` que actúa como AAD en el cifrado de la llave privada.
 *
 * Incluye todos los metadatos del keystore excepto el ciphertext de la llave privada.
 * Se serializa con `fast-json-stable-stringify` y se usa como AAD en XChaCha20-Poly1305,
 * garantizando que si cualquier campo es modificado (salt, nonce, iteraciones, llave pública),
 * el descifrado de la llave privada falle con un error de autenticación.
 *
 * @interface KeyStorageAad
 * @internal
 */
interface KeyStorageAad {
	metadata: {
		/** Tipo de llave almacenada. */
		key_type: "Ed25519";
		/** Fecha de generación de la llave (formato `toDateString()`). */
		generated_at: string;
	};
	kdf_parameters: {
		algorithm: "PBKDF2";
		hash: "SHA-256";
		/** Número de iteraciones PBKDF2. 2^19 = 524,288. */
		iterations: 524288;
		/** Longitud de la llave derivada en bytes. */
		key_length_bytes: 32;
	};
	privateKey_encryption: {
		algorithm: "XChacha20+Poly1305";
		tag_size_bytes: 16;
	};
	/**
	 * Salt de 16 bytes en Base64 para PBKDF2.
	 * Generado aleatoriamente; garantiza que contraseñas iguales
	 * produzcan llaves derivadas distintas.
	 */
	salt: string;
	/** Nonce de 192 bits para XChaCha20-Poly1305, en Base64. */
	nonce: string;
	/** Llave pública Ed25519 del par generado, en Base64. Almacenada en texto plano. */
	public_key: string;
}

/**
 * Estructura completa del almacenamiento seguro de llave privada.
 *
 * Este objeto puede ser persistido (localStorage, archivo JSON, base de datos)
 * de forma segura: la llave privada está cifrada con una llave derivada de
 * la contraseña del usuario, y los metadatos están autenticados como AAD.
 *
 * **Formato:**
 * ```json
 * {
 *   "metadata": { "key_type": "Ed25519", "generated_at": "..." },
 *   "kdf_parameters": { "algorithm": "PBKDF2", "iterations": 524288, ... },
 *   "privateKey_encryption": { "algorithm": "XChacha20+Poly1305", ... },
 *   "salt": "<base64 16 bytes>",
 *   "nonce": "<base64 24 bytes>",
 *   "public_key": "<base64 32 bytes>",
 *   "encryptedPrivateKey_w_tag": "<base64 ciphertext+tag>"
 * }
 * ```
 *
 * @interface KeyStorage
 */
export interface KeyStorage extends KeyStorageAad {
	/**
	 * Llave privada Ed25519 cifrada con XChaCha20-Poly1305 + tag Poly1305, en Base64.
	 * Los últimos 16 bytes son el authentication tag.
	 * Solo puede descifarse con la contraseña correcta mediante {@link CryptoModule.getPrivateKey}.
	 */
	encryptedPrivateKey_w_tag: string;
}

/**
 * Datos de un usuario destinatario para operaciones de cifrado.
 * @interface UserInfo
 * @internal
 */
interface UserInfo {
	username: string;
	/** Llave pública Ed25519 raw (32 bytes). */
	publicKey: Uint8Array;
}

/**
 * Datos de entrada para cifrar un archivo.
 *
 *
 * A diferencia de D3, ya no es necesario
 * pasar la información del propietario como mínimo en el atributo de destinatario.
 *
 * @interface CipherObject
 */
export interface CipherObject {
	/** Contenido del archivo en bytes. */
	data: Uint8Array;
	/** Tipo MIME del archivo. */
	file_type: string;
	/** Nombre del archivo. */
	filename: string;
	/**
	 * Lista opcional de destinatarios adicionales.
	 * Si se omite o está vacía, solo el propietario puede descifrar.
	 */
	recipients?: UserInfo[];
}

// Esquemas Zod

/**
 * Esquema Zod para validar la estructura completa de un `SignContainer`.
 *
 * Usado por {@link CryptoModule.verify_container_structure} para validar
 * que un objeto JSON tiene todos los campos requeridos antes de intentar
 * cualquier operación criptográfica.
 *
 * @internal
 */
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
			}),
		),
		nonce: z.string(),
	}),
	cipherText_w_tag: z.string(),
	signature_algo: z.string(),
	signer_id: z.string(),
	signature: z.string(),
});

/**
 * Esquema Zod para validar la estructura de un `KeyStorage`.
 *
 * Usado por {@link CryptoModule.verify_key_container_structure} antes de
 * intentar descifrar la llave privada, evitando errores criptográficos
 * por datos malformados.
 *
 * @internal
 */
const KeyStorageSchema = z.object({
	metadata: z.object({ key_type: z.string(), generated_at: z.string() }),
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
	encryptedPrivateKey_w_tag: z.string(),
});

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
 * Módulo central de D6 que integra gestión segura de llaves con cifrado híbrido,
 * ECIES-style y firma digital Ed25519.
 *
 * **Principio de diseño: la llave privada nunca se almacena en texto plano.**
 * Todas las operaciones que requieren la llave privada reciben un `KeyStorage`
 * (llave cifrada) y una contraseña. La llave se descifra en memoria solo para
 * esa operación y no se guarda en ninguna variable de instancia.
 *
 * **Jerarquía de operaciones:**
 * ```
 * generate_key_pair(password)     → KeyStorage (almacenable)
 * getPrivateKey(storage, pwd)     → Uint8Array (en memoria, temporal)
 * create_container(...)           → SignContainer (distribuible)
 * decrypt_container(...)          → Uint8Array (plaintext)
 * add/update/remove_recipients()  → SignContainer (actualizado y re-firmado)
 * ```
 *
 * @class CryptoModule
 */
export class CryptoModule {
	/**
	 * Genera un par de llaves Ed25519 y almacena la llave privada cifrada.
	 *
	 * **Flujo interno:**
	 * 1. `ed25519.keygen()` genera el par de llaves.
	 * 2. Se genera salt (16 bytes) y nonce (24 bytes) aleatorios.
	 * 3. `PBKDF2-SHA256(password, salt, 524288 iter, 32 bytes)` → `derivedKey`.
	 * 4. Se construye el objeto `aad` (metadatos del keystore).
	 * 5. `XChaCha20-Poly1305(derivedKey, nonce, AAD=stringify(aad))` cifra la llave privada.
	 * 6. Se retorna `KeyStorage` con todo lo necesario para descifrar (excepto la contraseña).
	 *
	 * La llave pública se almacena en texto plano en `public_key` porque es seguro
	 * distribuirla. La llave privada solo existe como `encryptedPrivateKey_w_tag`.
	 *
	 * @param password - Contraseña del usuario para derivar la llave de cifrado.
	 * @param expiration_data - Fecha de expiración de la llave (parámetro reservado, no implementado).
	 * @returns `KeyStorage` con la llave privada cifrada y todos los metadatos del KDF.
	 *
	 * @example
	 * ```ts
	 * const module = new CryptoModule();
	 * const storage = module.generate_key_pair("mi_contraseña_segura");
	 * // Persistir 'storage' en localStorage, archivo JSON, etc.
	 * ```
	 */
	generate_key_pair(password: string, expiration_data?: Date): KeyStorage {
		const keyPair = ed25519.keygen();
		const salt = randomBytes(16);
		const nonce = randomBytes(24);
		const derivedKey = pbkdf2(sha256, password, salt, {
			c: 524288,
			dkLen: 32,
		});

		const aad: KeyStorageAad = {
			metadata: {
				key_type: "Ed25519",
				generated_at: new Date().toDateString(),
			},
			kdf_parameters: {
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
			public_key: bytesToB64(keyPair.publicKey),
		};

		const aadDump = new TextEncoder().encode(stringify(aad));
		const chacha = xchacha20poly1305(derivedKey, nonce, aadDump);
		const encrypted_privateKey = chacha.encrypt(keyPair.secretKey);

		return {
			...aad,
			encryptedPrivateKey_w_tag: bytesToB64(encrypted_privateKey),
		};
	}

	/**
	 * Descifra y retorna la llave privada Ed25519 desde un `KeyStorage`.
	 *
	 * Re-deriva la llave de cifrado usando los parámetros almacenados en el
	 * `KeyStorage` (salt, iteraciones, hash) y la contraseña provista, luego
	 * descifra la llave privada con XChaCha20-Poly1305.
	 *
	 * Si la contraseña es incorrecta o el `KeyStorage` fue modificado, el tag
	 * Poly1305 no verifica y la librería lanza un error criptográfico.
	 *
	 * @param secureKeyStorage - Objeto `KeyStorage` con la llave privada cifrada.
	 * @param password - Contraseña del usuario.
	 * @returns Llave privada Ed25519 en bytes crudos (32 bytes), solo en memoria.
	 *
	 * @throws Error si la contraseña es incorrecta o el `KeyStorage` fue alterado.
	 *
	 * @example
	 * ```ts
	 * const privateKey = module.getPrivateKey(storage, "mi_contraseña");
	 * // Usar privateKey para firmar o descifrar, luego dejarla salir de scope
	 * ```
	 */
	getPrivateKey(secureKeyStorage: KeyStorage, password: string): Uint8Array {
		const salt = b64ToBytes(secureKeyStorage.salt);
		const nonce = b64ToBytes(secureKeyStorage.nonce);
		const derivedKey = pbkdf2(sha256, password, salt, {
			c: 524288,
			dkLen: 32,
		});

		const { encryptedPrivateKey_w_tag, ...aad } = secureKeyStorage;
		const data_ = b64ToBytes(encryptedPrivateKey_w_tag);
		const aadDump = new TextEncoder().encode(stringify(aad));

		const chacha = xchacha20poly1305(derivedKey, nonce, aadDump);
		return chacha.decrypt(data_);
	}

	/**
	 * Actualiza la contraseña de un `KeyStorage` sin cambiar el par de llaves.
	 *
	 * Descifra la llave privada con la contraseña actual y la re-cifra con
	 * la nueva contraseña, generando un nuevo salt y nonce aleatorios.
	 * La llave pública permanece igual.
	 *
	 * @param secureKeyStore - `KeyStorage` actual a re-cifrar.
	 * @param old_password - Contraseña actual (para verificar identidad antes de cambiar).
	 * @param new_password - Nueva contraseña con la que cifrar la llave privada.
	 * @returns Nuevo `KeyStorage` con la misma llave privada pero cifrada con la nueva contraseña.
	 *
	 * @throws Error `"Hubo un problema, no se pudo actualizar la contraseña"` si `old_password`
	 *   es incorrecta o si ocurre cualquier error durante el proceso.
	 *
	 * @example
	 * ```ts
	 * const newStorage = module.update_keystorage_password(storage, "vieja", "nueva");
	 * // Reemplazar 'storage' persistido con 'newStorage'
	 * ```
	 */
	update_keystorage_password(
		secureKeyStore: KeyStorage,
		old_password: string,
		new_password: string,
	): KeyStorage {
		try {
			const private_key = this.getPrivateKey(
				secureKeyStore,
				old_password,
			);
			const salt = randomBytes(16);
			const nonce = randomBytes(24);
			const derivedKey = pbkdf2(sha256, new_password, salt, {
				c: 524288,
				dkLen: 32,
			});

			const aad: KeyStorageAad = {
				metadata: {
					key_type: "Ed25519",
					generated_at: new Date().toDateString(),
				},
				kdf_parameters: {
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
				public_key: secureKeyStore.public_key,
			};

			const aadDump = new TextEncoder().encode(stringify(aad));
			const chacha = xchacha20poly1305(derivedKey, nonce, aadDump);
			const encrypted_privateKey = chacha.encrypt(private_key);

			return {
				...aad,
				encryptedPrivateKey_w_tag: bytesToB64(encrypted_privateKey),
			};
		} catch (err) {
			throw Error(
				"Hubo un problema, no se pudo actualizar la contraseña",
			);
		}
	}

	/**
	 * Retorna la llave pública Ed25519 desde un `KeyStorage` sin requerir contraseña.
	 *
	 * La llave pública se almacena en texto plano en `KeyStorage.public_key` porque
	 * es seguro exponerla. Este método simplemente la decodifica de Base64 a bytes.
	 *
	 * @param secureKeyStorage - `KeyStorage` del usuario.
	 * @returns Llave pública Ed25519 en bytes crudos (32 bytes).
	 */
	getPublicKey(secureKeyStorage: KeyStorage): Uint8Array {
		return b64ToBytes(secureKeyStorage.public_key);
	}

	/**
	 * Serializa una llave pública Ed25519 a formato SPKI PEM.
	 *
	 * Importa los bytes crudos como `CryptoKey` y los exporta en formato SPKI DER
	 * codificado en Base64 con cabecera PEM estándar.
	 *
	 * @param rawKey - Llave pública Ed25519 en bytes crudos (32 bytes).
	 * @returns Llave en formato SPKI PEM (`-----BEGIN PUBLIC KEY-----`).
	 */
	async serialize_public_key_pem(rawKey: Uint8Array): Promise<string> {
		const spkiObject: CryptoKey = await globalThis.crypto.subtle.importKey(
			"raw",
			rawKey.buffer as ArrayBuffer,
			"Ed25519",
			true,
			[],
		);
		const spkiDer = await globalThis.crypto.subtle.exportKey(
			"spki",
			spkiObject,
		);
		const exportedAsBase64 = bytesToB64(new Uint8Array(spkiDer));
		return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
	}

	/**
	 * Deserializa una llave pública Ed25519 desde formato SPKI PEM a bytes crudos.
	 *
	 * @param pem - Llave en formato SPKI PEM.
	 * @returns Llave pública Ed25519 en bytes crudos (32 bytes).
	 * @throws Error si el PEM no tiene la cabecera `-----BEGIN PUBLIC KEY-----`.
	 */
	async deserialize_public_key_pem(pem: string): Promise<Uint8Array> {
		const pemHeader = "-----BEGIN PUBLIC KEY-----";
		const pemFooter = "-----END PUBLIC KEY-----";
		if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
			throw new Error("La clave no tiene estructura PEM");
		}
		const pemContents = pem
			.substring(pemHeader.length, pem.length - pemFooter.length)
			.replace(/\s/g, "");
		const binaryDer = b64ToBytes(pemContents);
		const cryptoKey = await globalThis.crypto.subtle.importKey(
			"spki",
			binaryDer.buffer as ArrayBuffer,
			"Ed25519",
			true,
			[],
		);
		const rawKey = await globalThis.crypto.subtle.exportKey(
			"raw",
			cryptoKey,
		);
		return new Uint8Array(rawKey);
	}

	/**
	 * Cifra un archivo usando ECIES-style con `ownerWrap` separado.
	 *
	 * **Flujo:**
	 * ```
	 * 1. Generar symmetric_key (32 bytes) y nonce (24 bytes)
	 * 2. ownerWrap: ECIES(ephiPriv_owner, ownerXPub) → wrappedKey para el propietario
	 * 3. Para cada recipient: ECIES(ephiPriv_i, recipientXPub_i) → wrappedKey_i
	 * 4. AAD = stringify({ file_type, filename, timestamp, owner_fingerprint,
	 *                       ownerWrap, encryption, keyWrapping })
	 *    NOTA: recipients y nonce NO están en el AAD, están en metaData
	 * 5. cipherText_w_tag = XChaCha20-Poly1305(symmetric_key, nonce, AAD)
	 * ```
	 *
	 * @param cipherObject - Archivo y destinatarios (puede omitirse si solo cifra para el owner).
	 * @param owner_publicKey - Llave pública Ed25519 raw del propietario.
	 * @returns `cipherText_w_tag` (bytes) y `metaData` listos para empaquetar.
	 *
	 * @internal Llamado por {@link create_container}. No usar directamente.
	 */
	encrypt_file(
		cipherObject: CipherObject,
		owner_publicKey: Uint8Array,
	): { cipherText_w_tag: Uint8Array; metaData: EncryptionMetadata } {
		const symmetric_key = randomBytes(32);
		const nonce = randomBytes(24);

		// ownerWrap: par efímero independiente para el propietario
		const ephimeralKeyPair = x25519.keygen();
		const ephimeralPriv = ephimeralKeyPair.secretKey;
		const ephimeralPub = ephimeralKeyPair.publicKey;
		const ownerXPub = ed25519.utils.toMontgomery(owner_publicKey);
		const sharedSecret = x25519.getSharedSecret(ephimeralPriv, ownerXPub);
		const derivedKey = hkdf(sha256, sharedSecret, undefined, undefined, 32);
		const wrapNonce = randomBytes(24);

		const ownerWrap = {
			wrapNonce: bytesToB64(wrapNonce),
			wrappedKey: bytesToB64(
				xchacha20(derivedKey, wrapNonce, symmetric_key),
			),
			ephimeral_pub: bytesToB64(ephimeralPub),
		};

		// recipientsKeyWraps: par efímero independiente por destinatario
		const recipientsKeyWraps: KeyWrap[] = [];
		for (const recipient of cipherObject.recipients ?? []) {
			const ephiKeyPair = x25519.keygen();
			const ephiPriv = ephiKeyPair.secretKey;
			const ephiPub = ephiKeyPair.publicKey;
			const recipientXPub = ed25519.utils.toMontgomery(
				recipient.publicKey,
			);
			const secret = x25519.getSharedSecret(ephiPriv, recipientXPub);
			const dKey = hkdf(sha256, secret, undefined, undefined, 32);
			const wrapnonce = randomBytes(24);
			recipientsKeyWraps.push({
				username: recipient.username,
				wrapNonce: bytesToB64(wrapnonce),
				wrappedKey: bytesToB64(
					xchacha20(dKey, wrapnonce, symmetric_key),
				),
				ephimeral_pub: bytesToB64(ephiPub),
			});
		}

		const specs: AAD = {
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
			keyWrapping: {
				scheme: "ECIES-STYLE",
				asymmetric: {
					curve: "X25519",
					kdf: { alg: "HKDF", hash: "SHA-256", salt: "" },
				},
				symmetric: { cipher: "XChacha20", key_size_bits: 256 },
			},
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
	 * Descifra un contenedor firmado para el propietario o un destinatario autorizado.
	 *
	 * **Lógica de selección del KeyWrap:**
	 * - Si `petitioner_userName === container.signer_id` (el propietario pide descifrar):
	 *   usa `container.metaData.ownerWrap` directamente.
	 * - Si no: busca al peticionario en `metaData.recipients` por username.
	 *
	 * **Flujo completo:**
	 * 1. Verifica la firma Ed25519 del contenedor con {@link validate_container_signature}.
	 * 2. Descifra la llave privada del peticionario desde su `KeyStorage`.
	 * 3. Convierte la llave privada Ed25519 a X25519 (`toMontgomerySecret`).
	 * 4. ECDH con `ephimeral_pub` → HKDF → llave de unwrap.
	 * 5. XChaCha20 unwrap → `symmetric_key`.
	 * 6. Reconstruye el AAD (solo los campos del objeto `AAD`, sin `recipients` ni `nonce`).
	 * 7. XChaCha20-Poly1305 decrypt → plaintext.
	 *
	 * @param container - Contenedor firmado producido por {@link create_container}.
	 * @param petitioner_userName - Nombre del usuario que quiere descifrar.
	 * @param petitioner_secureKeyStorage - `KeyStorage` del peticionario.
	 * @param password - Contraseña del peticionario para descifrar su llave privada.
	 * @param owner_publicKey - Llave pública Ed25519 del firmante, para verificar firma.
	 * @returns Plaintext del archivo en bytes.
	 *
	 * @throws Error `"Firma no valida"` si la firma Ed25519 no verifica.
	 * @throws Error `"Recipient not found in metadata"` si el usuario no es el propietario
	 *   ni está en la lista de destinatarios.
	 * @throws Error criptográfico si la contraseña, los metadatos o el ciphertext son incorrectos.
	 */
	decrypt_container(
		container: SignContainer,
		petitioner_userName: string,
		petitioner_secureKeyStorage: KeyStorage,
		password: string,
		owner_publicKey: Uint8Array,
	): Uint8Array {
		if (!this.validate_container_signature(container, owner_publicKey))
			throw new Error("Firma no valida");

		const metaData = container.metaData;

		let petitioner_KeyWrap: KeyWrap | typeof metaData.ownerWrap | undefined;
		if (petitioner_userName === container.signer_id) {
			petitioner_KeyWrap = metaData.ownerWrap;
		} else {
			petitioner_KeyWrap = metaData.recipients.find(
				(r) => r.username === petitioner_userName,
			);
		}

		if (!petitioner_KeyWrap)
			throw new Error("Recipient not found in metadata");

		const petitioner_privateKey = this.getPrivateKey(
			petitioner_secureKeyStorage,
			password,
		);
		const petitionerXPriv = ed25519.utils.toMontgomerySecret(
			petitioner_privateKey,
		);
		const ephimeralPub = b64ToBytes(petitioner_KeyWrap.ephimeral_pub);
		const sharedSecret = x25519.getSharedSecret(
			petitionerXPriv,
			ephimeralPub,
		);
		const derivedKey = hkdf(sha256, sharedSecret, undefined, undefined, 32);
		const symmetric_key = xchacha20(
			derivedKey,
			b64ToBytes(petitioner_KeyWrap.wrapNonce),
			b64ToBytes(petitioner_KeyWrap.wrappedKey),
		);

		const cipherText_w_tag = b64ToBytes(container.cipherText_w_tag);
		const nonce = b64ToBytes(metaData.nonce);

		const payload: AAD = {
			file_type: metaData.file_type,
			filename: metaData.filename,
			timestamp: metaData.timestamp,
			owner_fingerprint: metaData.owner_fingerprint,
			ownerWrap: metaData.ownerWrap,
			encryption: metaData.encryption,
			keyWrapping: metaData.keyWrapping,
		};

		const aad = new TextEncoder().encode(stringify(payload));
		const chacha = xchacha20poly1305(symmetric_key, nonce, aad);
		return chacha.decrypt(cipherText_w_tag);
	}

	/**
	 *
	 * Obtiene la llave privada del propietario desde su `KeyStorage`, la usa para
	 * cifrar (via {@link encrypt_file}) y firmar el contenedor resultante.
	 *
	 * **Payload firmado (canonicalizado):**
	 * ```ts
	 * { metaData, cipherText_w_tag, signature_algo: "Ed25519", signer_id }
	 * ```
	 *
	 * @param secureKeyStorage - `KeyStorage` del propietario.
	 * @param password - Contraseña del propietario.
	 * @param owner_username - Nombre de usuario del propietario, almacenado en `signer_id`.
	 * @param cipherObject - Archivo y destinatarios a cifrar.
	 * @returns `SignContainer` con ciphertext firmado y metadatos completos.
	 *
	 * @example
	 * ```ts
	 * const module = new CryptoModule();
	 * const storage = module.generate_key_pair("mi_password");
	 * const container = module.create_container(storage, "mi_password", "alice", {
	 *   data: fileBytes,
	 *   filename: "informe.pdf",
	 *   file_type: "application/pdf",
	 *   recipients: [{ username: "bob", publicKey: bobPubKey }],
	 * });
	 * ```
	 */
	create_container(
		secureKeyStorage: KeyStorage,
		password: string,
		owner_username: string,
		cipherObject: CipherObject,
	): SignContainer {
		const owner_privateKey = this.getPrivateKey(secureKeyStorage, password);
		const owner_publicKey = ed25519.getPublicKey(owner_privateKey);
		const { cipherText_w_tag, metaData } = this.encrypt_file(
			cipherObject,
			owner_publicKey,
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
		const signature = bytesToB64(
			ed25519.sign(payloadDump, owner_privateKey),
		);

		return { ...payload, signature } as SignContainer;
	}

	/**
	 * Actualiza las llaves envueltas de destinatarios existentes en el contenedor.
	 *
	 * Útil cuando un destinatario ha rotado su par de llaves: genera un nuevo par
	 * efímero y re-envuelve la llave simétrica del archivo para la nueva llave pública.
	 * Solo puede ejecutarlo el propietario (usa su `ownerWrap` para recuperar la llave simétrica).
	 * El contenedor se re-firma tras la actualización.
	 *
	 * @param container - Contenedor a actualizar (debe tener firma válida del propietario).
	 * @param owner_secureKeyStorage - `KeyStorage` del propietario.
	 * @param password - Contraseña del propietario.
	 * @param recipientsUpdate - Lista de destinatarios con sus **nuevas** llaves públicas.
	 *   Solo se actualizan los destinatarios cuyos usernames ya existen en el contenedor.
	 * @returns Nuevo `SignContainer` con las llaves actualizadas y re-firmado.
	 *
	 * @throws Error `"Firma no válida"` si la firma del contenedor no es del propietario.
	 * @throws Error `"No se puedieron actualizar las llaves"` si ocurre algún error interno.
	 */
	update_container_recipientKeys(
		container: SignContainer,
		owner_secureKeyStorage: KeyStorage,
		password: string,
		recipientsUpdate: UserInfo[],
	): SignContainer {
		const publicKey = b64ToBytes(owner_secureKeyStorage.public_key);
		if (!this.validate_container_signature(container, publicKey))
			throw new Error("Firma no válida");

		const updatedContainer: SignContainer = structuredClone(container);

		try {
			const privateKey = this.getPrivateKey(
				owner_secureKeyStorage,
				password,
			);
			const xPriv = ed25519.utils.toMontgomerySecret(privateKey);
			const ephimeralPub = b64ToBytes(
				container.metaData.ownerWrap.ephimeral_pub,
			);
			const sharedSecret = x25519.getSharedSecret(xPriv, ephimeralPub);
			const wrapNonce = b64ToBytes(
				container.metaData.ownerWrap.wrapNonce,
			);
			const derivedKey = hkdf(
				sha256,
				sharedSecret,
				undefined,
				undefined,
				32,
			);
			const symmetric_key = xchacha20(
				derivedKey,
				wrapNonce,
				b64ToBytes(container.metaData.ownerWrap.wrappedKey),
			);

			const updatesMap = new Map<string, UserInfo>(
				recipientsUpdate.map((r) => [r.username, r]),
			);

			updatedContainer.metaData.recipients =
				container.metaData.recipients.map((recipient) => {
					const update = updatesMap.get(recipient.username);
					if (update) {
						const ephiKeyPair = x25519.keygen();
						const recipientXPub = ed25519.utils.toMontgomery(
							update.publicKey,
						);
						const secret = x25519.getSharedSecret(
							ephiKeyPair.secretKey,
							recipientXPub,
						);
						const dKey = hkdf(
							sha256,
							secret,
							undefined,
							undefined,
							32,
						);
						const newWrapNonce = randomBytes(24);
						return {
							username: recipient.username,
							wrapNonce: bytesToB64(newWrapNonce),
							wrappedKey: bytesToB64(
								xchacha20(dKey, newWrapNonce, symmetric_key),
							),
							ephimeral_pub: bytesToB64(ephiKeyPair.publicKey),
						};
					}
					return { ...recipient };
				});

			const { signature, ...payload } = updatedContainer;
			const payloadDump = new TextEncoder().encode(stringify(payload));
			updatedContainer.signature = bytesToB64(
				ed25519.sign(payloadDump, privateKey),
			);
		} catch (err) {
			throw new Error("No se puedieron actualizar las llaves");
		}

		return updatedContainer;
	}

	/**
	 * Añade nuevos destinatarios a un contenedor existente sin re-cifrar el archivo.
	 *
	 * Recupera la llave simétrica del archivo desde el `ownerWrap`, genera un nuevo
	 * par efímero X25519 por cada nuevo destinatario, envuelve la llave simétrica
	 * con la llave pública de cada uno y añade las entradas a `metaData.recipients`.
	 * Los destinatarios ya existentes no se modifican. El contenedor se re-firma.
	 *
	 * @param container - Contenedor existente (debe tener firma válida del propietario).
	 * @param owner_secureKeyStorage - `KeyStorage` del propietario.
	 * @param password - Contraseña del propietario.
	 * @param recipientsInfo - Lista de nuevos destinatarios a añadir.
	 *   Si un username ya existe en el contenedor, se ignora (no se duplica).
	 * @returns Nuevo `SignContainer` con los destinatarios añadidos y re-firmado.
	 *
	 * @throws Error `"Firma no válida"` si la firma no corresponde al propietario.
	 * @throws Error `"No se puedieron actualizar las llaves"` si ocurre algún error interno.
	 */
	add_recipients_to_container(
		container: SignContainer,
		owner_secureKeyStorage: KeyStorage,
		password: string,
		recipientsInfo: UserInfo[],
	): SignContainer {
		const publicKey = b64ToBytes(owner_secureKeyStorage.public_key);
		if (!this.validate_container_signature(container, publicKey))
			throw new Error("Firma no válida");

		const updatedContainer: SignContainer = structuredClone(container);

		try {
			const privateKey = this.getPrivateKey(
				owner_secureKeyStorage,
				password,
			);
			const xPriv = ed25519.utils.toMontgomerySecret(privateKey);
			const ephimeralPub = b64ToBytes(
				container.metaData.ownerWrap.ephimeral_pub,
			);
			const sharedSecret = x25519.getSharedSecret(xPriv, ephimeralPub);
			const wrapNonce = b64ToBytes(
				container.metaData.ownerWrap.wrapNonce,
			);
			const derivedKey = hkdf(
				sha256,
				sharedSecret,
				undefined,
				undefined,
				32,
			);
			const symmetric_key = xchacha20(
				derivedKey,
				wrapNonce,
				b64ToBytes(container.metaData.ownerWrap.wrappedKey),
			);

			const usersInList = new Set<string>(
				updatedContainer.metaData.recipients.map((r) => r.username),
			);

			for (const newRecipient of recipientsInfo) {
				if (!usersInList.has(newRecipient.username)) {
					const ephiKeyPair = x25519.keygen();
					const recipientXPub = ed25519.utils.toMontgomery(
						newRecipient.publicKey,
					);
					const secret = x25519.getSharedSecret(
						ephiKeyPair.secretKey,
						recipientXPub,
					);
					const dKey = hkdf(sha256, secret, undefined, undefined, 32);
					const newWrapNonce = randomBytes(24);
					updatedContainer.metaData.recipients.push({
						username: newRecipient.username,
						wrapNonce: bytesToB64(newWrapNonce),
						wrappedKey: bytesToB64(
							xchacha20(dKey, newWrapNonce, symmetric_key),
						),
						ephimeral_pub: bytesToB64(ephiKeyPair.publicKey),
					});
				}
			}

			const { signature, ...payload } = updatedContainer;
			const payloadDump = new TextEncoder().encode(stringify(payload));
			updatedContainer.signature = bytesToB64(
				ed25519.sign(payloadDump, privateKey),
			);
		} catch (err) {
			throw new Error("No se puedieron actualizar las llaves");
		}

		return updatedContainer;
	}

	/**
	 * Elimina destinatarios de un contenedor sin re-cifrar el archivo.
	 *
	 * Filtra la lista `metaData.recipients` excluyendo los usernames indicados
	 * y re-firma el contenedor con la llave privada del propietario.
	 *
	 * @param container - Contenedor existente (debe tener firma válida del propietario).
	 * @param owner_secureKeyStorage - `KeyStorage` del propietario.
	 * @param password - Contraseña del propietario.
	 * @param usernamesToRemove - Lista de usernames a eliminar de los destinatarios.
	 * @returns Nuevo `SignContainer` sin los destinatarios eliminados y re-firmado.
	 *
	 * @throws Error `"Firma no válida"` si la firma no corresponde al propietario.
	 * @throws Error `"No se pudo remover a los usuarios"` si ocurre algún error interno.
	 *
	 * @remarks
	 * Eliminar un destinatario revoca su acceso a **futuras versiones** del contenedor,
	 * pero si el destinatario ya guardó una copia previa del contenedor, seguirá
	 * pudiendo descifrarla. Para revocación total, el propietario debe re-cifrar
	 * el archivo con una nueva llave simétrica (crear un nuevo contenedor).
	 */
	remove_recipients_from_container(
		container: SignContainer,
		owner_secureKeyStorage: KeyStorage,
		password: string,
		usernamesToRemove: string[],
	): SignContainer {
		const publicKey = b64ToBytes(owner_secureKeyStorage.public_key);
		if (!this.validate_container_signature(container, publicKey))
			throw new Error("Firma no válida");

		const updatedContainer: SignContainer = structuredClone(container);

		try {
			const privateKey = this.getPrivateKey(
				owner_secureKeyStorage,
				password,
			);
			const usersToRemove = new Set<string>(usernamesToRemove);

			updatedContainer.metaData.recipients =
				updatedContainer.metaData.recipients.filter(
					(r) => !usersToRemove.has(r.username),
				);

			const { signature, ...payload } = updatedContainer;
			const payloadDump = new TextEncoder().encode(stringify(payload));
			updatedContainer.signature = bytesToB64(
				ed25519.sign(payloadDump, privateKey),
			);
		} catch (err) {
			throw new Error("No se pudo remover a los usuarios");
		}

		return updatedContainer;
	}

	/**
	 * Verifica criptográficamente la firma Ed25519 de un contenedor.
	 *
	 * **Pasos:**
	 * 1. Decodifica el `owner_fingerprint` de los metadatos del contenedor.
	 * 2. Calcula SHA-256 de la `owner_publicKey` provista.
	 * 3. Compara con `equalBytes` — si no coinciden, retorna `false`.
	 * 4. Reconstruye el payload canónico: `{ metaData, cipherText_w_tag, signature_algo, signer_id }`.
	 * 5. Verifica la firma Ed25519 con `fast-json-stable-stringify` del payload.
	 *
	 * @param container - Contenedor firmado a verificar.
	 * @param owner_publicKey - Llave pública Ed25519 raw del firmante esperado.
	 * @returns `true` si el fingerprint coincide y la firma es válida; `false` en caso contrario.
	 */
	validate_container_signature(
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

	/**
	 * Valida la estructura de un objeto candidato a `SignContainer` usando Zod.
	 *
	 * Verifica que todos los campos requeridos existan y tengan el tipo correcto,
	 * **sin** verificar la firma criptográfica. Útil para validar JSON recibido
	 * de la red antes de intentar operaciones criptográficas costosas.
	 *
	 * @param container - Objeto a validar (puede ser un JSON parseado de origen externo).
	 * @returns `true` si el objeto cumple el esquema `SignContainerSchema`; `false` si no.
	 *
	 * @example
	 * ```ts
	 * const parsed = JSON.parse(receivedJson);
	 * if (!module.verify_container_structure(parsed)) {
	 *   throw new Error("Contenedor malformado");
	 * }
	 * // Ahora es seguro intentar validate_container_signature(parsed, pubKey)
	 * ```
	 */
	verify_container_structure(container: object): boolean {
		return SignContainerSchema.safeParse(container).success;
	}

	/**
	 * Valida la estructura de un objeto candidato a `KeyStorage` usando Zod.
	 *
	 * Verifica que todos los campos requeridos existan y tengan el tipo correcto,
	 * **sin** intentar descifrar la llave privada. Útil para validar un `KeyStorage`
	 * cargado de localStorage o de un archivo antes de llamar a {@link getPrivateKey}.
	 *
	 * @param container - Objeto a validar.
	 * @returns `true` si el objeto cumple el esquema `KeyStorageSchema`; `false` si no.
	 *
	 * @example
	 * ```ts
	 * const loaded = JSON.parse(localStorage.getItem("keystore") ?? "{}");
	 * if (!module.verify_key_container_structure(loaded)) {
	 *   throw new Error("KeyStorage inválido o corrupto");
	 * }
	 * const privateKey = module.getPrivateKey(loaded as KeyStorage, password);
	 * ```
	 */
	verify_key_container_structure(container: object): boolean {
		return KeyStorageSchema.safeParse(container).success;
	}
}
