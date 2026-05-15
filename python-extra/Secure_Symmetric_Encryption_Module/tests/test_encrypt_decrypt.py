import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from encryption_module import SecureEncryption


def test_encrypt_decrypt():
    crypto = SecureEncryption()
        
    with open("test.txt", "w") as example: 
        example.write('Esto es confidencial')
    
    if os.path.exists("decrypted_test.txt"):
        os.remove("decrypted_test.txt")

    key = crypto.generate_key()
    container = crypto.encrypt_file("test.txt",key)
    crypto.decrypt_file(container, key, "decrypted_test.txt")

    with open("test.txt", "rb") as f1:
        original = f1.read()

    with open("decrypted_test.txt", "rb") as f2:
        decrypted = f2.read()

    assert original == decrypted