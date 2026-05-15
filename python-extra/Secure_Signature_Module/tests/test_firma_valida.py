import sys
import os
from Secure_Signature_Module.signature_module import SignedHybridEncryption, SignatureManager
from Secure_Hybrid_Encryption_Module.hybrid_encryption_module import KeyManager

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

def test_firma_valida_archivo_aceptado():
    crypto = SignedHybridEncryption()
    key_manager = KeyManager()
    sig_manager = SignatureManager()

    with open("test.txt", "w") as f:
        f.write("Esto es confidencial")

    output = "decrypted_test.txt"
    if os.path.exists(output):
        os.remove(output)

    alice_priv, alice_pub = key_manager.generate_rsa_key_pair()
    signing_priv, signing_pub = sig_manager.generate_signing_key_pair()

    container = crypto.encrypt_and_sign(
        "test.txt",
        {"alice": alice_pub},
        "alice",
        signing_priv,
    )

    crypto.verify_and_decrypt(container, signing_pub, "alice", alice_priv, output)

    with open("test.txt", "rb") as f:
        original = f.read()
    with open(output, "rb") as f:
        decrypted = f.read()

    assert original == decrypted

    os.remove("test.txt")
    os.remove(output)
