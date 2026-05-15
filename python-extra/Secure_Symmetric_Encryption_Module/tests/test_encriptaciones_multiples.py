import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from encryption_module import SecureEncryption

def test_encryptaciones_multiples(): 
    crypto = SecureEncryption()

    with open("test.txt", "w") as example: 
        example.write('Esto es confidencial')
    
    if os.path.exists("decrypted_test.txt"):
        os.remove("decrypted_test.txt")

    key = crypto.generate_key()
    container1 = crypto.encrypt_file("test.txt", key)
    container2 = crypto.encrypt_file("test.txt", key)

    assert container1["nonce"] != container2["nonce"]
    assert container1["ciphertext"] != container2["ciphertext"]
