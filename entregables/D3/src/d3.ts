/**
 * @fileoverview D3 — Módulo de Cifrado Híbrido Multi-Destinatario
 *
 * Extiende D1 añadiendo distribución de llaves por destinatario mediante RSA-OAEP.
 * Combina cifrado simétrico (XChaCha20-Poly1305) para el archivo con cifrado
 * asimétrico (RSA-OAEP / SubtleCrypto) para la llave simétrica, una vez por destinatario.
 *
 * **Por qué cifrado híbrido:**
 * RSA-OAEP no puede cifrar archivos arbitrariamente grandes (límite ~190 bytes para
 * RSA-2048). XChaCha20-Poly1305 es rápido y sin límite de tamaño. La solución es
 * cifrar el archivo **una sola vez** con AES/ChaCha y la llave pequeña
 * **una vez por destinatario** con RSA.
 *
 * **Gestión de llaves RSA:**
 * Este módulo usa la Web Crypto API (`SubtleCrypto`) para RSA. Las llaves se
 * representan internamente como `CryptoKey` opacos y se exportan/importan en
 * formato SPKI/PKCS#8 PEM para serialización estándar (RFC 5958).
 *
 * **Canonicalización:**
 * Los metadatos completos (incluyendo lista de destinatarios y nonce) se serializan
 * con `fast-json-stable-stringify` antes de usarlos como AAD en XChaCha20-Poly1305.
 * Esto significa que añadir, quitar o reordenar destinatarios invalida el tag
 * y hace imposible el descifrado.
 *
 * @module d3
 */

import { randomBytes } from "@noble/ciphers/utils.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import stringify from "fast-json-stable-stringify";
import { z } from "zod";


const KeyWrapSchema = z.object({
  username:   z.string(),
  wrappedKey: z.string(),
})

const ContainerSchema = z.object({
  metaData: z.object({
    filename:   z.string(),
    file_type:  z.string(),
    timestamp:  z.string(),
    encryption: z.string(),
    symmetric: z.object({
      cipher:           z.string(),
      key_size_bits:    z.number(),
      nonce_size_bytes: z.number(),
      tag_size_bytes:   z.number(),
    }),
    asymmetric: z.object({
      cipher:           z.string(),
      key_size_bits:    z.number(),
      public_exponent:  z.number(),
      hash:             z.string(),
      mgf:              z.string(),
    }),
    nonce:      z.string(),
    recipients: z.array(KeyWrapSchema).min(1),
  }),
  cipherText_w_tag: z.string(),
})


// Interfaces internas

/**
 * Información de un destinatario para el proceso de cifrado.
 * @interface UserInfo
 * @internal
 */
interface UserInfo {
	/** Nombre de usuario único que identifica al destinatario en los metadatos. */
	username: string;
	/** Llave pública RSA-OAEP del destinatario como objeto Web Crypto opaco. */
	publicKey: CryptoKey;
}

/**
 * Parámetros del algoritmo simétrico, incluidos en los metadatos como AAD.
 * @interface SymmetricMetadata
 * @internal
 */
interface SymmetricMetadata {
	cipher: string;
	key_size_bits: number;
	nonce_size_bytes: number;
	tag_size_bytes: number;
}

/**
 * Parámetros del algoritmo asimétrico, incluidos en los metadatos como AAD.
 * @interface AsymmetricMetadata
 * @internal
 */
interface AsymmetricMetadata {
	cipher: string;
	key_size_bits: number;
	public_exponent: number;
	hash: string;
	mgf: string;
}

/**
 * Entrada de la llave simétrica cifrada para un destinatario específico.
 *
 * Cada entrada almacena la llave simétrica envuelta con la llave pública
 * RSA-OAEP del destinatario correspondiente.
 *
 * @interface KeyWrap
 * @internal
 */
interface KeyWrap {
	/** Nombre del destinatario, usado como identificador durante el descifrado. */
	username: string;
	/** Llave simétrica cifrada con RSA-OAEP, codificada en Base64. */
	wrappedKey: string;
}

/**
 * Metadatos completos del contenedor cifrado.
 *
 * Se serializa completo (incluyendo `recipients`) con `fast-json-stable-stringify`
 * y se usa como **AAD** en XChaCha20-Poly1305. Cualquier modificación posterior
 * (añadir/quitar/reordenar destinatarios, cambiar parámetros) invalida el tag Poly1305.
 *
 * @interface EncryptionMetadata
 * @internal
 */
interface EncryptionMetadata {
	file_type: string;
	filename: string;
	/** Timestamp ISO-8601 del momento del cifrado. */
	timestamp: string;
	encryption: "Hybrid";
	symmetric: SymmetricMetadata;
	asymmetric: AsymmetricMetadata;
	/** Nonce de 192 bits en Base64. */
	nonce: string;
	/** Lista de destinatarios con sus llaves simétricas envueltas. */
	recipients: KeyWrap[];
}

// Interfaces exportadas

/**
 * Datos de entrada para cifrar un archivo para múltiples destinatarios.
 *
 * @interface CipherObject
 */
export interface CipherObject {
	/** Contenido del archivo en bytes. */
	data: Uint8Array;
	/** Nombre original del archivo, protegido por el AAD. */
	filename: string;
	/** Tipo MIME del archivo, protegido por el AAD. */
	file_type: string;
	/**
	 * Lista de destinatarios autorizados a descifrar el archivo.
	 * Debe contener al menos un elemento; de lo contrario,
	 * {@link HybridEncryption.encrypt_file} lanza un error.
	 */
	recipients: UserInfo[];
}

/**
 * Contenedor de salida producido por {@link HybridEncryption.encrypt_file}.
 *
 * Contiene todo lo necesario para que cualquier destinatario autorizado
 * pueda descifrar el archivo: metadatos (con las llaves simétricas envueltas
 * por destinatario) y el ciphertext con su tag de autenticación.
 *
 * @interface Container
 */
export interface Container {
	/**
	 * Metadatos del cifrado.
	 * Incluyen parámetros del algoritmo, nonce y llaves envueltas por destinatario.
	 * Usados como AAD durante el descifrado; no deben modificarse.
	 */
	metaData: EncryptionMetadata;
	/**
	 * Ciphertext + tag Poly1305 concatenados en Base64.
	 * Los últimos 16 bytes corresponden al authentication tag.
	 */
	cipherText_w_tag: string;
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

// Gestión de llaves RSA

/**
 * Gestiona la generación, exportación e importación de pares de llaves RSA-OAEP
 * usando la Web Crypto API (`SubtleCrypto`).
 *
 * Todas las llaves RSA se representan en formato PKCS#8/SPKI PEM para compatibilidad
 * con estándares (RFC 5958). Las operaciones son asíncronas porque `SubtleCrypto`
 * opera sobre promesas.
 *
 * @class KeyManager
 */
export class KeyManager {
	/**
	 * Genera un par de llaves RSA-OAEP de 2048 bits.
	 *
	 * Parámetros fijos:
	 * - Módulo: 2048 bits
	 * - Exponente público: 65537 (`[1, 0, 1]`)
	 * - Hash: SHA-256
	 * - Usos: `encrypt` (pública) / `decrypt` (privada)
	 *
	 * @returns Par de llaves RSA como objetos `CryptoKey` opacos de Web Crypto.
	 *
	 * @example
	 * ```ts
	 * const km = new KeyManager();
	 * const { publicKey, privateKey } = await km.generate_key_pair();
	 * ```
	 */
	async generate_key_pair(): Promise<{
		publicKey: CryptoKey;
		privateKey: CryptoKey;
	}> {
		const keyPair = await globalThis.crypto.subtle.generateKey(
			{
				name: "RSA-OAEP",
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256",
			},
			true,
			["encrypt", "decrypt"],
		);
		return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
	}

	/**
	 * Exporta una llave pública RSA al formato SPKI PEM.
	 *
	 * El formato producido es compatible con OpenSSL y la mayoría de herramientas
	 * criptográficas estándar. La cabecera es `-----BEGIN PUBLIC KEY-----`.
	 *
	 * @param publicCryptoKey - Llave pública `CryptoKey` generada por {@link generate_key_pair}.
	 * @returns Llave pública en formato SPKI PEM (string multi-línea).
	 *
	 * @example
	 * ```ts
	 * const pem = await km.exportPublicKey(publicKey);
	 * // "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
	 * ```
	 */
	async exportPublicKey(publicCryptoKey: CryptoKey): Promise<string> {
		const exported = await globalThis.crypto.subtle.exportKey(
			"spki",
			publicCryptoKey,
		);
		const exportedAsBase64 = bytesToB64(new Uint8Array(exported));
		return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
	}

	/**
	 * Exporta una llave privada RSA al formato PKCS#8 PEM.
	 *
	 * La cabecera producida es `-----BEGIN PRIVATE KEY-----` (PKCS#8, no PKCS#1).
	 * Este formato puede importarse con {@link importPrivateKey}.
	 *
	 * @param privateCryptoKey - Llave privada `CryptoKey` generada por {@link generate_key_pair}.
	 * @returns Llave privada en formato PKCS#8 PEM (string multi-línea).
	 */
	async exportPrivateKey(privateCryptoKey: CryptoKey): Promise<string> {
		const exported = await globalThis.crypto.subtle.exportKey(
			"pkcs8",
			privateCryptoKey,
		);
		const exportedAsBase64 = bytesToB64(new Uint8Array(exported));
		return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
	}

	/**
	 * Importa una llave pública RSA desde formato SPKI PEM.
	 *
	 * Valida que el PEM tenga la cabecera y pie correctos antes de importar.
	 * La llave resultante solo permite la operación `encrypt`.
	 *
	 * @param pem - Llave pública en formato SPKI PEM.
	 * @returns Objeto `CryptoKey` apto para cifrado RSA-OAEP.
	 * @throws Error si el PEM no tiene la estructura `-----BEGIN PUBLIC KEY-----`.
	 */
	async importPublicKey(pem: string): Promise<CryptoKey> {
		const pemHeader = "-----BEGIN PUBLIC KEY-----";
		const pemFooter = "-----END PUBLIC KEY-----";
		if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
			throw new Error("La clave no tiene estructura PEM");
		}
		const pemContents = pem
			.substring(pemHeader.length, pem.length - pemFooter.length)
			.replace(/\s/g, "");
		const binaryDer = b64ToBytes(pemContents);
		return globalThis.crypto.subtle.importKey(
			"spki",
			binaryDer.buffer as ArrayBuffer,
			{ name: "RSA-OAEP", hash: "SHA-256" },
			true,
			["encrypt"],
		);
	}

	/**
	 * Importa una llave privada RSA desde formato PKCS#8 PEM.
	 *
	 * Valida la estructura PEM antes de importar.
	 * La llave resultante solo permite la operación `decrypt`.
	 *
	 * @param pem - Llave privada en formato PKCS#8 PEM.
	 * @returns Objeto `CryptoKey` apto para descifrado RSA-OAEP.
	 * @throws Error si el PEM no tiene la estructura `-----BEGIN PRIVATE KEY-----`.
	 */
	async importPrivateKey(pem: string): Promise<CryptoKey> {
		const pemHeader = "-----BEGIN PRIVATE KEY-----";
		const pemFooter = "-----END PRIVATE KEY-----";
		if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
			throw new Error("La clave no tiene estructura PEM");
		}
		const pemContents = pem
			.substring(pemHeader.length, pem.length - pemFooter.length)
			.replace(/\s/g, "");
		const binaryDer = b64ToBytes(pemContents);
		return globalThis.crypto.subtle.importKey(
			"pkcs8",
			binaryDer.buffer as ArrayBuffer,
			{ name: "RSA-OAEP", hash: "SHA-256" },
			true,
			["decrypt"],
		);
	}
}

// Cifrado híbrido

/**
 * Implementa cifrado híbrido multi-destinatario combinando:
 * - **XChaCha20-Poly1305** (AEAD) para cifrar el archivo una sola vez.
 * - **RSA-OAEP / SubtleCrypto** para cifrar la llave simétrica por cada destinatario.
 *
 * **Flujo de cifrado:**
 * ```
 * 1. Generar file_key (32 bytes aleatorios)
 * 2. Cifrar el archivo: XChaCha20-Poly1305(file_key, nonce, AAD=metaData)
 * 3. Para cada destinatario: RSA-OAEP.encrypt(recipientPublicKey, file_key)
 * 4. Empaquetar en Container { metaData, cipherText_w_tag }
 * ```
 *
 * **Flujo de descifrado:**
 * ```
 * 1. Buscar entrada del destinatario en metaData.recipients por username
 * 2. RSA-OAEP.decrypt(recipientPrivateKey, wrappedKey) → file_key
 * 3. XChaCha20-Poly1305.decrypt(file_key, nonce, AAD=metaData) → plaintext
 * ```
 *
 * @class HybridEncryption
 */
export class HybridEncryption {
	/**
	 * Cifra un archivo para múltiples destinatarios usando cifrado híbrido.
	 *
	 * El archivo se cifra **una sola vez** con una llave simétrica aleatoria.
	 * Esa llave se envuelve con RSA-OAEP **una vez por destinatario**.
	 * Los metadatos completos (incluyendo la lista de destinatarios) actúan
	 * como AAD, garantizando que no puedan ser modificados retroactivamente.
	 *
	 * @param cipherObject - Archivo y destinatarios autorizados.
	 * @returns Contenedor con ciphertext y metadatos listos para distribuir.
	 * @throws Error si `cipherObject.recipients` está vacío.
	 *
	 * @example
	 * ```ts
	 * const enc = new HybridEncryption();
	 * const km = new KeyManager();
	 *
	 * const alice = await km.generate_key_pair();
	 * const bob   = await km.generate_key_pair();
	 *
	 * const container = await enc.encrypt_file({
	 *   data: new TextEncoder().encode("Secreto"),
	 *   filename: "secreto.txt",
	 *   file_type: "text/plain",
	 *   recipients: [
	 *     { username: "alice", publicKey: alice.publicKey },
	 *     { username: "bob",   publicKey: bob.publicKey },
	 *   ],
	 * });
	 * ```
	 */
	async encrypt_file(cipherObject: CipherObject): Promise<Container> {
		if (cipherObject.recipients.length === 0) {
			throw new Error("No recipients provided for encryption.");
		}

		const key = randomBytes(32);
		const nonce = randomBytes(24);
		const recipientsWrappedKeys: KeyWrap[] = [];

		for (const recipient of cipherObject.recipients) {
			const encryptedKeyRecipient =
				await globalThis.crypto.subtle.encrypt(
					{ name: "RSA-OAEP" },
					recipient.publicKey,
					key,
				);
			recipientsWrappedKeys.push({
				username: recipient.username,
				wrappedKey: bytesToB64(new Uint8Array(encryptedKeyRecipient)),
			});
		}

		const metaData: EncryptionMetadata = {
			file_type: cipherObject.file_type,
			filename: cipherObject.filename,
			timestamp: new Date().toISOString(),
			encryption: "Hybrid",
			symmetric: {
				cipher: "XChacha20-Poly1305",
				key_size_bits: 256,
				nonce_size_bytes: 24,
				tag_size_bytes: 16,
			},
			asymmetric: {
				cipher: "RSA-OAEP",
				key_size_bits: 2048,
				public_exponent: 65537,
				hash: "SHA-256",
				mgf: "MGF1-SHA256",
			},
			nonce: btoa(String.fromCharCode(...nonce)),
			recipients: recipientsWrappedKeys,
		};

		const aad = new TextEncoder().encode(stringify(metaData));
		const chacha = xchacha20poly1305(key, nonce, aad);
		const cipherText_w_tag = chacha.encrypt(cipherObject.data);

		return { metaData, cipherText_w_tag: bytesToB64(cipherText_w_tag) };
	}

	/**
	 * Descifra un archivo usando la llave privada de un destinatario autorizado.
	 *
	 * Busca la entrada del destinatario por `recipientUsername` en la lista
	 * `metaData.recipients`, desenvuelve la llave simétrica con RSA-OAEP y
	 * usa XChaCha20-Poly1305 para descifrar y autenticar el ciphertext.
	 *
	 * @param container - Contenedor producido por {@link encrypt_file}.
	 * @param recipientUsername - Nombre del destinatario que quiere descifrar.
	 * @param recipientPrivateKey - Llave privada RSA del destinatario.
	 * @returns Plaintext del archivo original en bytes.
	 *
	 * @throws Error `"Recipient not found in metadata"` si el username no está en la lista.
	 * @throws Error criptográfico si la llave privada no corresponde a la pública usada,
	 *   o si los metadatos del contenedor fueron modificados.
	 *
	 * @example
	 * ```ts
	 * const plaintext = await enc.decrypt_file(container, "alice", alice.privateKey);
	 * console.log(new TextDecoder().decode(plaintext)); // "Secreto"
	 * ```
	 */
	async decrypt_file(
		container: Container,
		recipientUsername: string,
		recipientPrivateKey: CryptoKey,
	): Promise<Uint8Array> {

		if(!this.verify_container_structure(container)) {
			throw new Error("Invalid container structure");
		}

		const metaData: EncryptionMetadata = container.metaData;
		const cipherText_w_tag = b64ToBytes(container.cipherText_w_tag);

		const recipientKeyWrap = metaData.recipients.find(
			(r) => r.username === recipientUsername,
		);
		if (!recipientKeyWrap)
			throw new Error("Recipient not found in metadata");

		const wrappedKeyBytes = b64ToBytes(recipientKeyWrap.wrappedKey);
		const nonce = b64ToBytes(metaData.nonce);

		const symmetricKeyBuffer = await globalThis.crypto.subtle.decrypt(
			{ name: "RSA-OAEP" },
			recipientPrivateKey,
			wrappedKeyBytes.buffer as ArrayBuffer,
		);

		const symmetricKey = new Uint8Array(symmetricKeyBuffer);
		const aad = new TextEncoder().encode(stringify(metaData));
		const chacha = xchacha20poly1305(symmetricKey, nonce, aad);
		return chacha.decrypt(cipherText_w_tag);
	}

	verify_container_structure(container: object): boolean {
		return ContainerSchema.safeParse(container).success;
	}
}
