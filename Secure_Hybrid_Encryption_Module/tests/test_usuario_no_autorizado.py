import sys
import os
import pytest
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from hybrid_encryption_module import HybridEncryption, KeyManager


def test_usuario_no_autorizado_no_puede_descifrar():
    crypto = HybridEncryption()
    key_manager = KeyManager()

    with open("test.txt", "w") as f:
        f.write("Esto es confidencial")

    alice_private, alice_public = key_manager.generate_rsa_key_pair()
    intruder_private, _ = key_manager.generate_rsa_key_pair()

    recipients = {"alice": alice_public}
    container = crypto.encrypt_file("test.txt", recipients)

    with pytest.raises(ValueError, match="no se encontró en el contenedor"):
        crypto.decrypt_file(container, "intruder", intruder_private, "decrypted_intruder.txt")

    os.remove("test.txt")
    if os.path.exists("decrypted_intruder.txt"):
        os.remove("decrypted_intruder.txt")
