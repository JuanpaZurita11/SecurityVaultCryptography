import sys
import os
import pytest
from cryptography.exceptions import InvalidSignature
from Secure_Signature_Module.signature_module import SignedHybridEncryption, SignatureManager
from Secure_Hybrid_Encryption_Module.hybrid_encryption_module import KeyManager

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

def test_llave_publica_incorrecta_rechazada():
    crypto = SignedHybridEncryption()
    key_manager = KeyManager()
    sig_manager = SignatureManager()

    with open("test.txt", "w") as f:
        f.write("Esto es confidencial")

    alice_priv, alice_pub = key_manager.generate_rsa_key_pair()
    signing_priv, signing_pub = sig_manager.generate_signing_key_pair()
    wrong_priv, wrong_pub = sig_manager.generate_signing_key_pair()

    container = crypto.encrypt_and_sign(
        "test.txt",
        {"alice": alice_pub},
        "alice",
        signing_priv,
    )

    with pytest.raises(InvalidSignature):
        crypto.verify_and_decrypt(container, wrong_pub, "alice", alice_priv, "decrypted_test.txt")

    os.remove("test.txt")
    if os.path.exists("decrypted_test.txt"):
        os.remove("decrypted_test.txt")
