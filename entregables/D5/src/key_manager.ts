/**
 * @fileoverview D5 — KeyManager para llaves Ed25519 en formato PKCS#8/SPKI PEM
 *
 * Gestiona la serialización y deserialización de llaves Ed25519 crudas
 * (`Uint8Array`) a formato PEM estándar, compatible con RFC 8410.
 *
 * **Diferencia con D3:**
 * D3 gestiona llaves RSA a través de `CryptoKey` opacos de Web Crypto.
 * Este módulo trabaja con llaves Ed25519 como bytes crudos (`Uint8Array`),
 * que es la representación nativa de `@noble/curves`. Las conversiones
 * PEM ↔ bytes permiten almacenar y distribuir llaves en formato estándar.
 *
 * **Formato de llave privada (PKCS#8 DER manual):**
 * La Web Crypto API no permite exportar llaves Ed25519 como bytes crudos directamente.
 * Para la llave pública se usa `SubtleCrypto.exportKey("spki")`. Para la llave privada,
 * se construye manualmente la estructura DER conforme al RFC 8410 (48 bytes fijos):
 * ```
 * SEQUENCE {
 *   INTEGER 0 (version)
 *   SEQUENCE { OID 1.3.101.112 (Ed25519) }
 *   OCTET STRING { OCTET STRING { rawPrivateKey[32 bytes] } }
 * }
 * ```
 * Al deserializar se importa el PKCS#8 para validar y luego se extraen los bytes
 * crudos cortando los primeros 16 bytes del encabezado DER.
 *
 * @module key_manager
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { b64ToBytes, bytesToB64 } from "./signature_crypto_module.js";

/**
 * Gestiona la generación y serialización de pares de llaves Ed25519
 * en formato PEM estándar (PKCS#8 para privadas, SPKI para públicas).
 *
 * Las llaves Ed25519 se representan internamente como `Uint8Array` de 32 bytes,
 * que es la representación nativa de `@noble/curves`. Los métodos de este módulo
 * convierten entre esa representación y cadenas PEM para almacenamiento y distribución.
 *
 * @class KeyManager
 */
export class KeyManager {
	/**
	 * Genera un par de llaves Ed25519 como bytes crudos.
	 *
	 * Usa `ed25519.keygen()` de `@noble/curves`, que internamente usa
	 * `crypto.getRandomValues` como fuente de entropía segura.
	 *
	 * @returns Par de llaves en bytes crudos (32 bytes cada una):
	 *   - `publicKey`: 32 bytes, llave pública Ed25519.
	 *   - `privateKey`: 32 bytes, llave privada (seed) Ed25519.
	 *
	 * @example
	 * ```ts
	 * const km = new KeyManager();
	 * const { publicKey, privateKey } = km.generate_key_pair();
	 * // publicKey.length  === 32
	 * // privateKey.length === 32
	 * ```
	 */
	generate_key_pair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
		const keyPair = ed25519.keygen();
		return { publicKey: keyPair.publicKey, privateKey: keyPair.secretKey };
	}

	// Serialización (Export)

	/**
	 * Serializa una llave pública Ed25519 a formato SPKI PEM.
	 *
	 * Importa los bytes crudos como `CryptoKey` con uso vacío `[]` (solo exportación),
	 * los exporta en formato SPKI DER y codifica el resultado en Base64 con cabecera PEM.
	 *
	 * El formato producido (`-----BEGIN PUBLIC KEY-----`) es compatible con OpenSSL
	 * y puede usarse directamente con `deserialize_public_key_pem`.
	 *
	 * @param rawKey - Llave pública Ed25519 en bytes crudos (32 bytes).
	 * @returns Llave pública en formato SPKI PEM (string multi-línea).
	 *
	 * @example
	 * ```ts
	 * const pem = await km.serialize_public_key_pem(publicKey);
	 * // "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----"
	 * ```
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
	 * Serializa una llave privada Ed25519 a formato PKCS#8 PEM.
	 *
	 * **Construcción manual del DER (RFC 8410):**
	 * La Web Crypto API requiere importar primero para luego exportar como PKCS#8,
	 * pero no admite importar llaves Ed25519 desde bytes crudos con uso `sign`.
	 * Por esto se construye manualmente el DER de 48 bytes con la estructura fija
	 * definida en RFC 8410 para Ed25519:
	 *
	 * ```
	 * Offset | Bytes          | Significado
	 * -------|----------------|---------------------------
	 *  0-1   | 30 2e          | SEQUENCE (46 bytes)
	 *  2-4   | 02 01 00       | INTEGER version = 0
	 *  5-6   | 30 05          | SEQUENCE AlgorithmIdentifier
	 *  7-8   | 06 03          | OID tag (3 bytes)
	 *  9-11  | 2b 65 70       | OID 1.3.101.112 (Ed25519)
	 * 12-13  | 04 22          | OCTET STRING outer (34 bytes)
	 * 14-15  | 04 20          | OCTET STRING inner (32 bytes)
	 * 16-47  | rawKey[0..31]  | Bytes crudos de la llave privada
	 * ```
	 *
	 * @param rawKey - Llave privada Ed25519 en bytes crudos (32 bytes).
	 * @returns Llave privada en formato PKCS#8 PEM.
	 *
	 * @example
	 * ```ts
	 * const pem = await km.serialize_private_key_pem(privateKey);
	 * // "-----BEGIN PRIVATE KEY-----\nMC4CAQ...\n-----END PRIVATE KEY-----"
	 * ```
	 */
	async serialize_private_key_pem(rawKey: Uint8Array): Promise<string> {
		const der = new Uint8Array([
			0x30,
			0x2e, // SEQUENCE (46 bytes)
			0x02,
			0x01,
			0x00, //   INTEGER version = 0
			0x30,
			0x05, //   SEQUENCE AlgorithmIdentifier
			0x06,
			0x03, //     OID tag + length
			0x2b,
			0x65,
			0x70, //     OID 1.3.101.112 (Ed25519)
			0x04,
			0x22, //   OCTET STRING outer (34 bytes)
			0x04,
			0x20, //     OCTET STRING inner (32 bytes)
			...rawKey, //     raw key bytes (32 bytes)
		]);
		const exportedAsBase64 = bytesToB64(der);
		return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
	}

	// Deserialización (Import)

	/**
	 * Deserializa una llave pública Ed25519 desde formato SPKI PEM a bytes crudos.
	 *
	 * Importa el PEM como `CryptoKey` y luego lo exporta como `"raw"` para obtener
	 * los 32 bytes de la llave pública Ed25519.
	 *
	 * @param pem - Llave pública en formato SPKI PEM con cabecera `-----BEGIN PUBLIC KEY-----`.
	 * @returns Llave pública Ed25519 en bytes crudos (32 bytes).
	 * @throws Error `"La clave no tiene estructura PEM"` si el PEM es inválido.
	 *
	 * @example
	 * ```ts
	 * const rawKey = await km.deserialize_public_key_pem(pemString);
	 * // Uint8Array de 32 bytes
	 * ```
	 */
	async deserialize_public_key_pem(pem: string): Promise<Uint8Array> {
		const pemHeader = "-----BEGIN PUBLIC KEY-----";
		const pemFooter = "-----END PUBLIC KEY-----";
		if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
			throw new Error("The key is not in PEM format");
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
	 * Deserializa una llave privada Ed25519 desde formato PKCS#8 PEM a bytes crudos.
	 *
	 * **Estrategia de extracción:**
	 * 1. Valida el formato PEM.
	 * 2. Importa el DER como `CryptoKey` PKCS#8 con uso `sign` (para validar integridad).
	 * 3. Re-exporta el DER desde la `CryptoKey` importada.
	 * 4. Corta los primeros 16 bytes del encabezado DER PKCS#8 con `slice(16)`,
	 *    obteniendo los 32 bytes crudos de la llave privada.
	 *
	 * @param pem - Llave privada en formato PKCS#8 PEM con cabecera `-----BEGIN PRIVATE KEY-----`.
	 * @returns Llave privada Ed25519 en bytes crudos (32 bytes).
	 * @throws Error `"La clave no tiene estructura PEM"` si el PEM es inválido.
	 *
	 * @remarks
	 * El `slice(16)` asume la estructura fija de 48 bytes de PKCS#8 para Ed25519 (RFC 8410).
	 * Los bytes 0-15 son el encabezado DER; los bytes 16-47 son la llave privada cruda.
	 *
	 * @example
	 * ```ts
	 * const rawKey = await km.deserialize_private_key_pem(pemString);
	 * // Uint8Array de 32 bytes
	 * ```
	 */
	async deserialize_private_key_pem(pem: string): Promise<Uint8Array> {
		const pemHeader = "-----BEGIN PRIVATE KEY-----";
		const pemFooter = "-----END PRIVATE KEY-----";
		if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
			throw new Error("The key is not in PEM format");
		}
		const pemContents = pem
			.substring(pemHeader.length, pem.length - pemFooter.length)
			.replace(/\s/g, "");
		const binaryDer = b64ToBytes(pemContents);
		const cryptoKey = await globalThis.crypto.subtle.importKey(
			"pkcs8",
			binaryDer.buffer as ArrayBuffer,
			"Ed25519",
			true,
			["sign"],
		);
		const exportedDer = new Uint8Array(
			await globalThis.crypto.subtle.exportKey("pkcs8", cryptoKey),
		);
		// Los primeros 16 bytes son el encabezado DER PKCS#8; los 32 restantes son la llave cruda
		return exportedDer.slice(16);
	}
}
