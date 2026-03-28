import os
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from datetime import datetime, timezone


class KeyManager:

    def generate_rsa_key_pair(self, key_size: int = 2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        return private_key, private_key.public_key()

    def serialize_private_key_pkcs8_pem(self, private_key, password: bytes = None):
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    def serialize_public_key_pem(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def load_private_key_from_pem(self, pem_data: bytes, password: bytes = None):
        return serialization.load_pem_private_key(pem_data, password=password)

    def load_public_key_from_pem(self, pem_data: bytes):
        return serialization.load_pem_public_key(pem_data)

    def get_key_fingerprint(self, public_key):
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(public_key_der).hexdigest()
        return digest


class HybridEncryption:

    def __init__(self):
        self.key_manager = KeyManager()

    def build_metadata(self, file_path: str, recipients_ids: list):
        filename = os.path.basename(file_path)
        timestamp = datetime.now(timezone.utc).isoformat()
        metadata = {
            "algorithm_version": "RSA-OAEP+AES-GCM-Hybrid",
            "encryption_parameters": {
                "asymmetric_algorithm": "RSA-OAEP",
                "hash_algorithm": "SHA-256",
                "mgf": "MGF1-SHA256",
                "symmetric_algorithm": "AES-GCM",
                "key_size_bits": 256,
                "nonce_size_bytes": 12,
                "tag_size_bytes": 16,
                "rsa_key_size_bits": 2048,
            },
            "filename": filename,
            "creation_timestamp": timestamp,
            "recipients_ids": sorted(recipients_ids),
        }
        return metadata

    def encrypt_file(self, file_path: str, recipients: dict):
        if not recipients:
            raise ValueError("Se requiere al menos un destinatario para cifrar el archivo.")

        with open(file_path, "rb") as f:
            plaintext = f.read()

        file_key = AESGCM.generate_key(bit_length=256)

        nonce = os.urandom(12)

        recipient_fingerprints = {}
        for recipient_id, public_key in recipients.items():
            fingerprint = self.key_manager.get_key_fingerprint(public_key)
            recipient_fingerprints[recipient_id] = fingerprint

        recipients_ids_for_aad = [
            f"{rid}:{rfp}" for rid, rfp in sorted(recipient_fingerprints.items())
        ]

        metadata = self.build_metadata(file_path, recipients_ids_for_aad)
        metadata_bytes = json.dumps(metadata, sort_keys=True).encode("utf-8")

        aesgcm = AESGCM(file_key)
        encryption = aesgcm.encrypt(nonce, plaintext, metadata_bytes)

        tag = encryption[-16:]
        ciphertext = encryption[:-16]

        encrypted_keys = []
        for recipient_id, public_key in recipients.items():
            fingerprint = recipient_fingerprints[recipient_id]
            encrypted_file_key = public_key.encrypt(
                file_key,
                OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            encrypted_keys.append(
                {
                    "id": recipient_id,
                    "key_fingerprint": fingerprint,
                    "encrypted_key": encrypted_file_key.hex(),
                }
            )

        container = {
            "metadata": metadata,
            "recipients": encrypted_keys,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex(),
        }
        return container

    def decrypt_file(
        self,
        container: dict,
        recipient_id: str,
        private_key,
        output_path: str = None,
    ):

        try:
            metadata = container["metadata"]
            recipients_list = container["recipients"]
            nonce = bytes.fromhex(container["nonce"])
            ciphertext = bytes.fromhex(container["ciphertext"])
            tag = bytes.fromhex(container["tag"])
        except KeyError as e:
            raise KeyError(f"El contenedor no tiene el campo requerido: {e}")

        recipient_entry = None
        for entry in recipients_list:
            if entry["id"] == recipient_id:
                recipient_entry = entry
                break

        if recipient_entry is None:
            raise ValueError(
                f"El destinatario '{recipient_id}' no se encontró en el contenedor."
            )

        public_key = private_key.public_key()
        actual_fingerprint = self.key_manager.get_key_fingerprint(public_key)
        expected_fingerprint = recipient_entry["key_fingerprint"]

        if actual_fingerprint != expected_fingerprint:
            raise InvalidTag(
                "Error de autenticación: el fingerprint de la llave privada no coincide "
                "con el registrado para este destinatario."
            )

        encrypted_file_key = bytes.fromhex(recipient_entry["encrypted_key"])
        try:
            file_key = private_key.decrypt(
                encrypted_file_key,
                OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception:
            raise InvalidTag(
                "Error: no se pudo descifrar la llave del archivo."
            )

        metadata_bytes = json.dumps(metadata, sort_keys=True).encode("utf-8")

        aesgcm = AESGCM(file_key)
        data_to_decrypt = ciphertext + tag

        try:
            plaintext = aesgcm.decrypt(nonce, data_to_decrypt, metadata_bytes)
        except InvalidTag:
            raise InvalidTag(
                "Error: autenticación fallida."
            )

        if output_path is None:
            filename = metadata.get("filename", "decrypted_file")
            output_path = os.path.join(os.getcwd(), f"decrypted_{filename}")

        with open(output_path, "wb") as f:
            f.write(plaintext)
    
        print(f"Archivo descifrado correctamente en: {output_path}")