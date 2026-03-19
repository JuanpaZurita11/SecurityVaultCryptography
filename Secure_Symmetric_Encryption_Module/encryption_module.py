import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from datetime import datetime,timezone

class SecureEncryption:

    def generate_key(self):
        return AESGCM.generate_key(bit_length=256)

    def build_metadata(self,file_path:str): 
        filename = os.path.basename(file_path)
        timestamp = datetime.now(timezone.utc).isoformat()
        metadata = {
            "algorithm_version": "AES-GCM",
            "encryption_parameters": {
                "key_size_bits": 256,
                "nonce_size_bytes": 12,
                "tag_size_bytes": 16
            },
            "filename": filename, 
            "creation_timestamp": timestamp
        }
        return metadata
    
    def encrypt_file(self, file_path, key):
        
        if not isinstance(key,bytes) or len(key) != 32: 
            raise ValueError("La llave debe ser de tipo bytes y tenere una longitud de 256 bits (32 bytes)")
        
        ## CipherText
        with open(file_path, "rb") as f:
            data = f.read()

        ## Initializtion Vector
        nonce = os.urandom(12)

        ## Additional Authenticated Data
        metadata = self.build_metadata(file_path)
        metadata_bytes = json.dumps(metadata,sort_keys=True).encode('utf-8')

        ## Algorithm
        aesgcm = AESGCM(key)
        encryption = aesgcm.encrypt(nonce, data, metadata_bytes)

        ## Authentication TAG
        tag = encryption[-16:]

        ## CipherText
        ciphertext = encryption[:-16]

        container = {
            "metadata": metadata,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(), 
            "tag": tag.hex()
        }
        return container

    def decrypt_file(self, container, key,filename=None, output_path=None):

        if not isinstance(key,bytes) or len(key) != 32: 
            raise ValueError("La llave debe ser de 256 bits.")
        
        try: 
            metadata = container["metadata"]

            if filename is None: 
                filename = metadata.get("filename","decrypted_file.txt")

            if output_path is None: 
                output_path = os.path.join(os.getcwd(),filename)
            else: 
                if os.path.isdir(output_path):
                    output_path = os.path.join(output_path,filename)
                else: 
                    raise NotADirectoryError(f"La ruta {output_path} no es un directorio válido")
            
            if os.path.exists(output_path) and filename != "decrypted_file.txt":
                raise FileExistsError(f"El archivo con ruta {output_path} ya existe. Operacion cancelada")
                          
            nonce = bytes.fromhex(container["nonce"])
            ciphertext = bytes.fromhex(container["ciphertext"])
            tag = bytes.fromhex(container["tag"])
        except KeyError as e: 
            raise KeyError(f"El contenedor no tiene el campo {e}")
        
        metadata_bytes = json.dumps(metadata,sort_keys=True).encode('utf-8')
        data_to_decrypt = ciphertext + tag 
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(nonce, data_to_decrypt, metadata_bytes)
            with open(output_path, "wb") as f:
                f.write(plaintext)
            print("Archivo descifrado correctamente")
        except InvalidTag:
            raise InvalidTag("Error: autenticación fallida. El archivo fue modificado o la clave es incorrecta")