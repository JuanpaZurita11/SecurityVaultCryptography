import os
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone
from Secure_Hybrid_Encryption_Module.hybrid_encryption_module import HybridEncryption, KeyManager


class SignatureManager:

    def generate_signing_key_pair(self):
        private_key = Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()

    def serialize_signing_private_key_pkcs8_pem(self, private_key, password: bytes = None):
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

    def serialize_signing_public_key_pem(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def load_signing_private_key_from_pem(self, pem_data: bytes, password: bytes = None):
        return serialization.load_pem_private_key(pem_data, password=password)

    def load_signing_public_key_from_pem(self, pem_data: bytes):
        return serialization.load_pem_public_key(pem_data)

    def get_signer_fingerprint(self, public_key):
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_key_der).hexdigest()

    def build_signable_payload(self, container: dict) -> bytes:
        payload = {
            "ciphertext": container["ciphertext"],
            "tag": container["tag"],
            "metadata": container["metadata"],
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def sign_container(self, container: dict, signer_id: str, private_key):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("La llave privada debe ser de tipo Ed25519PrivateKey.")

        payload = self.build_signable_payload(container)
        signature_bytes = private_key.sign(payload)

        signed_container = dict(container)
        signed_container["signature"] = signature_bytes.hex()
        signed_container["signer_id"] = signer_id
        signed_container["signer_fingerprint"] = self.get_signer_fingerprint(
            private_key.public_key()
        )
        return signed_container

    def verify_container(self, container: dict, public_key):
        try:
            signature_hex = container["signature"]
            signer_fingerprint = container["signer_fingerprint"]
        except KeyError as e:
            raise KeyError(f"El contenedor no tiene el campo de firma requerido: {e}")

        actual_fingerprint = self.get_signer_fingerprint(public_key)
        if actual_fingerprint != signer_fingerprint:
            raise InvalidSignature(
                "El fingerprint de la llave pública no coincide con el del firmante registrado."
            )

        payload = self.build_signable_payload(container)
        signature_bytes = bytes.fromhex(signature_hex)

        try:
            public_key.verify(signature_bytes, payload)
        except InvalidSignature:
            raise InvalidSignature(
                "Verificación fallida: la firma no es válida. "
                "El contenedor fue modificado o la llave pública es incorrecta."
            )


class SignedHybridEncryption:

    def __init__(self):
        self.hybrid = HybridEncryption()
        self.key_manager = KeyManager()
        self.signature_manager = SignatureManager()

    def encrypt_and_sign(
        self,
        file_path: str,
        recipients: dict,
        signer_id: str,
        signing_private_key,
    ):
        container = self.hybrid.encrypt_file(file_path, recipients)
        signed_container = self.signature_manager.sign_container(
            container, signer_id, signing_private_key
        )
        return signed_container

    def verify_and_decrypt(
        self,
        container: dict,
        signing_public_key,
        recipient_id: str,
        private_key,
        output_path: str = None,
    ):
        self.signature_manager.verify_container(container, signing_public_key)
        print("Firma verificada correctamente.")
        self.hybrid.decrypt_file(container, recipient_id, private_key, output_path)
