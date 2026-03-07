import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from encryption_module import SecureEncryption

def test_encrypt_decrypt():
    crypto = SecureEncryption()

    if os.path.exists("archivo_salida.txt"):
        os.remove("archivo_salida.txt")

    key = crypto.generate_key()
    container = crypto.encrypt_file("test.txt", key)
    crypto.decrypt_file(container, key, "archivo_salida.txt")

    with open("test.txt", "rb") as f1:
        original = f1.read()

    with open("archivo_salida.txt", "rb") as f2:
        decrypted = f2.read()

    assert original == decrypted