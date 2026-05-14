import sys
import os
import pytest 
from cryptography.exceptions import InvalidTag

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from encryption_module import SecureEncryption

def test_wrong_key_fail(): 
    crypto = SecureEncryption()

    with open("test.txt", "w") as example: 
        example.write('Esto es confidencial')
    
    if os.path.exists("decrypted_test.txt"):
        os.remove("decrypted_test.txt")

    key = crypto.generate_key()
    container = crypto.encrypt_file("test.txt", key)
    wrong_key = crypto.generate_key()

    with pytest.raises(InvalidTag):
        crypto.decrypt_file(container, wrong_key, "decrypted_test.txt")