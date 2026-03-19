import sys
import os
import copy
import pytest 
from cryptography.exceptions import InvalidTag

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from encryption_module import SecureEncryption

def test_texto_modificado():
    crypto = SecureEncryption()

    with open("test.txt", "w") as example: 
        example.write('Esto es confidencial')
    
    if os.path.exists("decrypted_test.txt"):
        os.remove("decrypted_test.txt")
   
    key = crypto.generate_key()
    container = crypto.encrypt_file("test.txt", key)
    ciphertext = bytearray.fromhex(container["ciphertext"])
    ciphertext[0] ^= 1
    container["ciphertext"] = ciphertext.hex()

    with pytest.raises(InvalidTag):
        crypto.decrypt_file(container, key, "decrypted_test.txt")