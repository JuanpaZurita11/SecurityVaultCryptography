import sys
import os
import copy

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from encryption_module import SecureEncryption

def test_metadata_modificada():
    crypto = SecureEncryption()

    if os.path.exists("salida_metadata_modificada.txt"):
        os.remove("salida_metadata_modificada.txt")

    key = crypto.generate_key()
    container = crypto.encrypt_file("test.txt", key)
    modified_container = copy.deepcopy(container)
    modified_container["metadata"]["filename"] = "archivo_modificado.txt"
    crypto.decrypt_file(modified_container, key, "salida_metadata_modificada.txt")

    assert not os.path.exists("salida_metadata_modificada.txt")