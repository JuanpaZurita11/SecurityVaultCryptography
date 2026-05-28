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
 * La lista de destinatarios ahora es protegida por la firma, lo que permite sacarla del AAD
 * y modificarla sin invalidar el tag del ciphertext.
 *
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
import { z } from "zod";

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


// Interfaces exportadas

/**
 * Datos de la llave simétrica envuelta para un destinatario específico.
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
 * Metadatos completos del contenedor cifrado, incluyendo lista de destinatarios.
 *
 * Extiende {@link AAD} añadiendo los campos que varían por cifrado:
 * La lista `recipients` puede ser modificada por el propietario sin
 * invalidar el tag del ciphertext, siempre que se re-firme el contenedor.
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
	/** Lista de destinatarios (nombre + llave pública Ed25519 raw). */
	recipients ?: UserInfo[];
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
	 * Se descartan las llaves (RSA-OAEP) de D3 y se utilizan llaves de firma Ed25519.
	 *
	 * Cifra un archivo para múltiples destinatarios usando ECIES-style.
	 * 1. Las llaves de firma Ed25519 se convierten a llaves de tipo X25519 para ECDH.
	 * 2. Se generan llaves efímeras por destinatario.
	 * 3. Se deriva un secreto (utilizando la llave efímera privada y la llave pública del destinatario) y se * usa para envolver la llave simétrica con XChaCha20.
	 *
	 * @param cipherObject - Archivo y destinatarios a cifrar.
	 * @param owner_fingerprint - SHA-256(owner_publicKey) en Base64, incluido en AAD.
	 * @returns Ciphertext con tag Poly1305 y metadatos listos para empaquetar.
	 *
	 * @internal Usar {@link create_container} para el flujo completo con firma.
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
	 * Descifra un contenedor firmado para un destinatario específico.
	 *
	 * **Flujo completo:**
	 * 1. Valida la firma Ed25519 del contenedor con {@link validate_container_signature}.
	 * 2. Busca la entrada del destinatario en `metaData.recipients`.
	 * 3. Convierte la llave privada Ed25519 a X25519 (`toMontgomerySecret`).
	 * 4. ECDH con la llave efímera pública → HKDF → llave de unwrap.
	 * 5. XChaCha20 unwrap → llave simétrica.
	 * 6. XChaCha20-Poly1305 decrypt → plaintext.
	 *
	 * @param container - Contenedor firmado producido por {@link create_container}.
	 * @param petitioner_userName - Nombre del destinatario que quiere descifrar.
	 * @param petitioner_privateKey - Llave privada Ed25519 raw (32 bytes) del destinatario.
	 * @param owner_publicKey - Llave pública Ed25519 raw del firmante, para verificar firma.
	 * @returns Plaintext del archivo en bytes.
	 *
	 * @throws Error `"Firma no valida"` si la firma Ed25519 no verifica.
	 * @throws Error `"Recipient not found in metadata"` si el usuario no está autorizado.
	 * @throws Error criptográfico si los metadatos o ciphertext fueron modificados.
	 */
	decrypt_container(
		container: SignContainer,
		petitioner_userName: string,
		petitioner_privateKey: Uint8Array,
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

		const petitionerXPriv =
			ed25519.utils.toMontgomerySecret(petitioner_privateKey);
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
	 *	Cifra y firma el contenedor en un solo paso.

	 * Al añadir el 'owner_fingerprint' (SHA-256 de la llave pública del propietario) en el AAD, se refuerza el vínculo entre la identidad del creador y el contenido cifrado.


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
		const signature = ed25519.sign(payloadDump, owner_privateKey);
		return {
			...payload,
			signature: bytesToB64(signature),
		} as SignContainer;
	}

	/**
   * Agrega nuevos destinatarios a un contenedor criptográfico firmado.
   * * Esta función valida la firma actual del contenedor, desencripta la llave simétrica
   * utilizando las credenciales del propietario (convirtiendo llaves Ed25519 a X25519),
   * y luego envuelve (encripta) esta llave simétrica para cada uno de los nuevos
   * destinatarios utilizando sus respectivas llaves públicas. Finalmente, actualiza
   * la lista de destinatarios y vuelve a firmar el contenedor modificado.
   *
   * @param container - El contenedor firmado original (`SignContainer`) que se desea actualizar.
   * @param owner_publicKey - La llave pública del propietario (Ed25519) en formato `Uint8Array`, utilizada para validar la firma inicial del contenedor.
   * @param owner_privateKey - La llave privada del propietario (Ed25519) en formato `Uint8Array`, utilizada para desencriptar la llave simétrica y firmar el contenedor resultante.
   * @param recipientsInfo - Un arreglo con la información de los usuarios (`UserInfo[]`) que se añadirán al contenedor.
   * @returns Un nuevo objeto `SignContainer` (clonado del original) que incluye a los nuevos destinatarios y una firma actualizada.
   * @throws {Error} Lanza un error con el mensaje "Firma no válida" si el contenedor original fue alterado o la llave pública no corresponde.
   * @throws {Error} Lanza un error con el mensaje "No se puedieron actualizar las llaves" si falla alguna operación criptográfica (ej. derivación de llaves, encriptación XChaCha20 o la nueva firma).
   */
	add_recipients_to_container(
		container: SignContainer,
		owner_publicKey: Uint8Array,
		owner_privateKey: Uint8Array,
		recipientsInfo: UserInfo[],
	): SignContainer {

		if (!this.validate_container_signature(container, owner_publicKey))
			throw new Error("Firma no válida");

		const updatedContainer: SignContainer = structuredClone(container);

		try {
			const xPriv = ed25519.utils.toMontgomerySecret(owner_privateKey);
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
				ed25519.sign(payloadDump, owner_privateKey),
			);
		} catch (err) {
			throw new Error("No se puedieron actualizar las llaves");
		}

		return updatedContainer;
	}

	/**
   * Elimina destinatarios específicos de un contenedor criptográfico firmado.
   * * Esta función primero valida la firma del contenedor original utilizando la llave
   * pública del propietario. Luego, filtra la lista de destinatarios actual para remover
   * a los usuarios cuyos nombres coincidan con los indicados. Finalmente, genera una
   * nueva firma para el contenedor modificado utilizando la llave privada del propietario,
   * garantizando así su integridad.
   *
   * @param container - El contenedor firmado original (`SignContainer`) del cual se eliminarán los destinatarios.
   * @param owner_publicKey - La llave pública del propietario en formato `Uint8Array`, utilizada para validar la firma inicial del contenedor.
   * @param owner_privateKey - La llave privada del propietario en formato `Uint8Array`, utilizada para generar la nueva firma del contenedor actualizado.
   * @param usernamesToRemove - Un arreglo de cadenas de texto (`string[]`) con los nombres de los usuarios que deben ser retirados del contenedor.
   * @returns Un nuevo objeto `SignContainer` (clonado del original) con la lista de destinatarios actualizada y una firma válida.
   * @throws {Error} Lanza un error con el mensaje "Firma no válida" si el contenedor original fue alterado o si la llave pública proporcionada no corresponde.
   * @throws {Error} Lanza un error con el mensaje "No se pudo remover a los usuarios" si ocurre algún fallo interno durante la eliminación o el proceso de re-firmado.
  */
	remove_recipients_from_container(
		container: SignContainer,
		owner_publicKey: Uint8Array,
		owner_privateKey: Uint8Array,
		usernamesToRemove: string[],
	): SignContainer {

		if (!this.validate_container_signature(container, owner_publicKey))
			throw new Error("Firma no válida");

		const updatedContainer: SignContainer = structuredClone(container);

		try {

			const usersToRemove = new Set<string>(usernamesToRemove);

			updatedContainer.metaData.recipients =
				updatedContainer.metaData.recipients.filter(
					(r) => !usersToRemove.has(r.username),
				);

			const { signature, ...payload } = updatedContainer;
			const payloadDump = new TextEncoder().encode(stringify(payload));
			updatedContainer.signature = bytesToB64(
				ed25519.sign(payloadDump, owner_privateKey),
			);
		} catch (err) {
			throw new Error("No se pudo remover a los usuarios");
		}

		return updatedContainer;
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
}
