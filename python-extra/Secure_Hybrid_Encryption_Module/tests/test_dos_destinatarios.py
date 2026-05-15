import sys
import os
import pytest
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from hybrid_encryption_module import HybridEncryption, KeyManager

def test_dos_destinatarios_pueden_descifrar():
    crypto = HybridEncryption()
    key_manager = KeyManager()

    with open("test.txt", "w") as f:
        f.write("Esto es un archivo de prueba")

    alice_output = "decrypted_alice.txt"
    bob_output = "decrypted_bob.txt"

    for path in [alice_output, bob_output]:
        if os.path.exists(path):
            os.remove(path)

    alice_private, alice_public = key_manager.generate_rsa_key_pair()
    bob_private, bob_public = key_manager.generate_rsa_key_pair()

    recipients = {
        "alice": alice_public,
        "bob": bob_public,
    }
    container = crypto.encrypt_file("test.txt", recipients)

    crypto.decrypt_file(container, "alice", alice_private, alice_output)

    crypto.decrypt_file(container, "bob", bob_private, bob_output)

    with open("test.txt", "rb") as f:
        original = f.read()

    with open(alice_output, "rb") as f:
        alice_decrypted = f.read()

    with open(bob_output, "rb") as f:
        bob_decrypted = f.read()

    assert original == alice_decrypted, "Alice no obtuvo el contenido original"
    assert original == bob_decrypted, "Bob no obtuvo el contenido original"

    os.remove("test.txt")
    os.remove(alice_output)
    os.remove(bob_output)
