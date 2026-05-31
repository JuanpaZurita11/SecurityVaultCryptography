/**
 * @fileoverview D1 — Módulo de Cifrado Simétrico Autenticado
 *
 * Implementa cifrado simétrico con autenticación usando XChaCha20-Poly1305 (AEAD).
 * Este módulo es la base del sistema de cifrado: protege archivos con una sola
 * llave simétrica de 256 bits y garantiza tanto confidencialidad como integridad.
 *
 * **Algoritmo:** XChaCha20-Poly1305
 * - Cifrado en flujo: XChaCha20 (256-bit key, 192-bit nonce)
 * - Autenticación: Poly1305 MAC (128-bit tag)
 * - Categoría: AEAD (Authenticated Encryption with Associated Data)
 *
 * **Canonicalización:** Los metadatos se serializan con `fast-json-stable-stringify`
 * (llaves ordenadas determinísticamente) antes de usarlos como AAD,
 * garantizando que el mismo objeto siempre produzca los mismos bytes.
 *
 * @module d1
 */

import { randomBytes } from "@noble/ciphers/utils.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import stringify from "fast-json-stable-stringify";
import {z} from "zod";



// Interfaces

/**
 * Datos de entrada requeridos para cifrar un archivo.
 *
 * @interface CipherObject
 */
export interface CipherObject {
	/** Contenido del archivo en bytes crudos. */
	data: Uint8Array;
	/** Nombre original del archivo, incluido en los metadatos y protegido por AAD. */
	filename: string;
	/** Tipo MIME del archivo (p. ej. `"application/pdf"`), protegido por AAD. */
	file_type: string;
}

/**
 * Metadatos que describen el proceso de cifrado.
 *
 * Este objeto se serializa con `fast-json-stable-stringify` y se usa como
 * **AAD (Additional Authenticated Data)** en XChaCha20-Poly1305.
 * Cualquier modificación posterior a estos campos invalida el tag Poly1305
 * y hace imposible el descifrado, garantizando integridad de los metadatos.
 *
 * @interface MetaData
 * @internal No se exporta; solo se usa internamente dentro de {@link Container}.
 */
interface MetaData {
	/** Nombre original del archivo. */
	filename: string;
	/** Tipo MIME del archivo. */
	file_type: string;
	/** Timestamp ISO-8601 del momento del cifrado (UTC). */
	timestamp: string;
	/** Identificador fijo del esquema de cifrado. */
	encryption: "Symmetric";
	/** Parámetros técnicos del algoritmo, incluidos en el AAD. */
	parameters: {
		/** Algoritmo AEAD utilizado. */
		cipher: "XChacha20+Poly1305";
		/** Longitud de la llave en bits. */
		key_size_bits: 256;
		/** Longitud del nonce en bytes. */
		nonce_size_bytes: 24;
		/** Longitud del tag de autenticación en bytes. */
		tag_size_bytes: 16;
	};
	/**
	 * Nonce de 192 bits codificado en Base64.
	 * Se genera aleatoriamente en cada cifrado; nunca se reutiliza.
	 */
	nonce: string;
}

/**
 * Contenedor de salida producido por {@link SymmetricEncryption.encrypt_file}.
 *
 * Almacena todo lo necesario para descifrar el archivo excepto la llave simétrica,
 * que debe mantenerse separada y protegida.
 *
 * @interface Container
 */
export interface Container {
	/** Metadatos del cifrado, usados como AAD durante el descifrado. */
	metaData: MetaData;
	/**
	 * Ciphertext + tag Poly1305 concatenados, codificados en Base64.
	 * Los últimos 16 bytes son el authentication tag de Poly1305.
	 */
	cipherText_w_tag: string;
}


const ContainerSchema = z.object({
  metaData: z.object({
    filename: z.string(),
    file_type: z.string(),
    timestamp: z.string(),
    encryption: z.string(),
    parameters: z.object({
      cipher: z.string(),
      key_size_bits: z.number(),
      nonce_size_bytes: z.number(),
      tag_size_bytes: z.number(),
    }),
    nonce: z.string(),
  }),
  cipherText_w_tag: z.string(),
});


// Utilidades de codificación

/**
 * Decodifica una cadena Base64 a un array de bytes.
 *
 * @param b64 - Cadena en formato Base64 estándar.
 * @returns Array de bytes decodificados.
 *
 * @example
 * ```ts
 * const bytes = b64ToBytes("SGVsbG8=");
 * // Uint8Array [72, 101, 108, 108, 111]
 * ```
 */
export function b64ToBytes(b64: string): Uint8Array {
	return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Codifica un array de bytes a una cadena Base64.
 *
 * @param bytes - Bytes a codificar.
 * @returns Representación Base64 de los bytes.
 *
 * @example
 * ```ts
 * const b64 = bytesToB64(new Uint8Array([72, 101, 108, 108, 111]));
 * // "SGVsbG8="
 * ```
 */
export function bytesToB64(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes));
}

// Clase principal

/**
 * Implementa cifrado y descifrado simétrico autenticado con XChaCha20-Poly1305.
 *
 * **Flujo de cifrado:**
 * ```
 * plaintext + key + nonce + AAD(metaData) → cipherText_w_tag
 * ```
 *
 * **Flujo de descifrado:**
 * ```
 * cipherText_w_tag + key + nonce + AAD(metaData) → plaintext
 * ```
 *
 * Si cualquier campo de `metaData` es modificado después del cifrado,
 * el tag Poly1305 no verifica y el descifrado falla con un error criptográfico.
 *
 * @class SymmetricEncryption
 */
export class SymmetricEncryption {

	/**
	 * Cifra un archivo usando XChaCha20-Poly1305 con metadatos como AAD.
	 *
	 * Genera internamente una llave simétrica de 256 bits y un nonce de 192 bits,
	 * ambos aleatorios y únicos para cada llamada. Los metadatos se incluyen como
	 * AAD, lo que garantiza su integridad: si son modificados después del cifrado,
	 * el descifrado falla.
	 *
	 * @param cipherObject - Datos del archivo a cifrar junto con su metadata.
	 * @returns Objeto con el {@link Container} cifrado y la `symmetricKey` en bytes.
	 *
	 * @remarks
	 * La `symmetricKey` retornada **nunca debe almacenarse junto al contenedor**.
	 * En D3 esta llave se envuelve (wraps) con RSA-OAEP por destinatario.
	 * En D6 se elimina este método y la llave la gestiona internamente `CryptoModule`.
	 *
	 * @example
	 * ```ts
	 * const enc = new SymmetricEncryption();
	 * const { container, symmetricKey } = enc.encrypt_file({
	 *   data: new TextEncoder().encode("Datos secretos"),
	 *   filename: "secreto.txt",
	 *   file_type: "text/plain",
	 * });
	 * // Guardar container; proteger symmetricKey por separado
	 * ```
	 */
	encrypt_file(cipherObject: CipherObject): {
		container: Container;
		symmetricKey: Uint8Array;
	} {
		const key = randomBytes(32);
		const nonce = randomBytes(24);

		const metaData: MetaData = {
			filename: cipherObject.filename,
			file_type: cipherObject.file_type,
			timestamp: new Date().toISOString(),
			encryption: "Symmetric",
			parameters: {
				cipher: "XChacha20+Poly1305",
				key_size_bits: 256,
				nonce_size_bytes: 24,
				tag_size_bytes: 16,
			},
			nonce: bytesToB64(nonce),
		};

		const aad = new TextEncoder().encode(stringify(metaData));
		const chacha = xchacha20poly1305(key, nonce, aad);
		const cipherText_w_tag = chacha.encrypt(cipherObject.data);

		const container: Container = {
			metaData,
			cipherText_w_tag: bytesToB64(cipherText_w_tag),
		};

		return { container, symmetricKey: key };
	}

	/**
	 * Descifra un contenedor usando la llave simétrica original.
	 *
	 * Reconstruye el AAD serializando los metadatos del contenedor con
	 * `fast-json-stable-stringify` (mismo proceso que en el cifrado) y verifica
	 * el tag Poly1305 antes de retornar el plaintext. Si los metadatos fueron
	 * alterados o la llave es incorrecta, la librería lanza un error.
	 *
	 * @param container - Contenedor producido por {@link encrypt_file}.
	 * @param symmetricKey - Llave simétrica de 32 bytes usada durante el cifrado.
	 * @returns Datos originales del archivo en bytes.
	 *
	 * @throws Error si la llave es incorrecta o si el contenedor fue modificado.
	 *
	 * @example
	 * ```ts
	 * const enc = new SymmetricEncryption();
	 * const plaintext = enc.decrypt_file(container, symmetricKey);
	 * console.log(new TextDecoder().decode(plaintext)); // "Datos secretos"
	 * ```
	 */
	decrypt_file(container: any, symmetricKey: Uint8Array): Uint8Array {
		if(!this.verify_container_structure(container)) {
			throw new Error("Invalid container structure");
		}

		const nonce = b64ToBytes(container.metaData.nonce);
		const aad = new TextEncoder().encode(stringify(container.metaData));
		const chacha = xchacha20poly1305(symmetricKey, nonce, aad);
		const data_ = b64ToBytes(container.cipherText_w_tag);
		return chacha.decrypt(data_);
	}

	verify_container_structure(container: object): boolean {
		return ContainerSchema.safeParse(container).success;
	}
}
