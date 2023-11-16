from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def encrypt_rsa(message, public_key_pem):
    # Wczytaj klucz publiczny z formatu PEM
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    # Zaszyfruj wiadomość za pomocą klucza publicznego
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Zwróć zaszyfrowaną wiadomość jako bajty
    return ciphertext

# Przykład użycia:
if __name__ == "__main__":
    # Przykładowa wiadomość do zaszyfrowania
    message_to_encrypt = "Hello, RSA encryption!"

    # Przykładowy klucz publiczny w formacie PEM
    public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7RXPiYF+Eyyml/hdxOBt\n0txafK51fI8WAyIb8VoM1Os4iWp/X384eSvZaQSi5qn0jVg87C9mXppHAebRgHrn\nNE5pKzQSR3cgEqZwEDCr1J3JO8F8k54QOFsjhZCBFjqem9oYmvXN8BKxGlkmym7l\n7lfLUeLrgM0uOh2gyR6E2lkC1l0FMuoUyRiOKkchqespVVA6dqOXNhZV2s2cu34B\nEqfIE1iBQtA93abBY6HD5ZoTPxfvtSMKPLwL/ZDXMljEtF+o1QB6kKRZKutIYjwQ\n3Ak1PSrSdw2eh5+FN+vqRP++uumpgT3MukIrgcOzf7X/M+jdhHKZcW90rN1bDgbl\n0wIDAQAB\n-----END PUBLIC KEY-----\n"

    # Zaszyfruj wiadomość przy użyciu klucza publicznego
    encrypted_message = encrypt_rsa(message_to_encrypt, public_key_pem)

    # Wyświetl zaszyfrowaną wiadomość
    print("Zaszyfrowana wiadomość:", encrypted_message.hex())
