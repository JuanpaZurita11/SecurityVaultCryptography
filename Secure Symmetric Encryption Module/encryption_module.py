import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from datetime import datetime

class SecureEncryption:

    # Genera una clave simetrica de 256 bits  nueva por archivo
    def generate_key(self):
        return AESGCM.generate_key(bit_length=256)

    def encrypt_file(self, file_path, key):
        with open(file_path, "rb") as f:
            data = f.read()
        nonce = os.urandom(12)
        metadata = {
            "filename": os.path.basename(file_path),
            "timestamp": datetime.utcnow().isoformat(),
            "algorithm": "AES-GCM"
        }

        metadata_bytes = json.dumps(metadata).encode()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, metadata_bytes)

        container = {
            "metadata": metadata,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }
        return container

    def decrypt_file(self, container, key, output_path):
        metadata = container["metadata"]
        nonce = bytes.fromhex(container["nonce"])
        ciphertext = bytes.fromhex(container["ciphertext"])
        metadata_bytes = json.dumps(metadata).encode()
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, metadata_bytes)
            with open(output_path, "wb") as f:
                f.write(plaintext)
            print("Archivo descifrado correctamente")
        except InvalidTag:
            print("Error: autenticación fallida. El archivo fue modificado o la clave es incorrecta")