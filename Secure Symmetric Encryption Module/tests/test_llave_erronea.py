import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from encryption_module import SecureEncryption

def test_llave_erronea():
    crypto = SecureEncryption()

    if os.path.exists("salida_llave_incorrecta.txt"):
        os.remove("salida_llave_incorrecta.txt")

    key = crypto.generate_key()
    container = crypto.encrypt_file("test.txt", key)
    wrong_key = crypto.generate_key()
    crypto.decrypt_file(container, wrong_key, "salida_llave_incorrecta.txt")

    assert not os.path.exists("salida_llave_incorrecta.txt")