import sys
import os
import copy

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from encryption_module import SecureEncryption

def test_texto_modificado():
    crypto = SecureEncryption()

    if os.path.exists("texto_modificado.txt"):
        os.remove("texto_modificado.txt")

    key = crypto.generate_key()
    container = crypto.encrypt_file("test.txt", key)
    modified_container = copy.deepcopy(container)
    ciphertext = bytearray.fromhex(modified_container["ciphertext"])
    ciphertext[0] ^= 1
    modified_container["ciphertext"] = ciphertext.hex()
    crypto.decrypt_file(modified_container, key, "texto_modificado.txt")

    assert not os.path.exists("texto_modificado.txt")