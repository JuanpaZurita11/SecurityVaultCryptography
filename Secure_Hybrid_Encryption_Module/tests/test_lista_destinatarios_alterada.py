import sys
import os
import copy
import pytest
from cryptography.exceptions import InvalidTag
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from hybrid_encryption_module import HybridEncryption, KeyManager


def test_lista_destinatarios_alterada_falla():
    crypto = HybridEncryption()
    key_manager = KeyManager()

    with open("test.txt", "w") as f:
        f.write("Esto es confidencial")

    alice_private, alice_public = key_manager.generate_rsa_key_pair()

    recipients = {"alice": alice_public}
    container = crypto.encrypt_file("test.txt", recipients)

    tampered_container = copy.deepcopy(container)
    tampered_container["metadata"]["recipients_ids"].append("attacker:fakefingerprint")

    with pytest.raises(InvalidTag):
        crypto.decrypt_file(tampered_container, "alice", alice_private, "decrypted_tampered.txt")

    os.remove("test.txt")
    if os.path.exists("decrypted_tampered.txt"):
        os.remove("decrypted_tampered.txt")
