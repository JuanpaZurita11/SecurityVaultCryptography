import sys
import os
import copy
import pytest
from cryptography.exceptions import InvalidTag

from datetime import datetime,timezone

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from encryption_module import SecureEncryption

def test_metadata_modificada():
    crypto = SecureEncryption()

    with open("test.txt", "w") as example: 
        example.write('Esto es confidencial')
    
    if os.path.exists("decrypted_test.txt"):
        os.remove("decrypted_test.txt")

    key = crypto.generate_key()
    container = crypto.encrypt_file("test.txt", key)
    modified_container = copy.deepcopy(container)
    modified_container["metadata"]["timestamp"] = datetime.now(timezone.utc).isoformat()
    
    with pytest.raises(InvalidTag):
        crypto.decrypt_file(modified_container, key, "decrypted_test.txt")