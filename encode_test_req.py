from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import requests
import json
import time
import base64
from requests.auth import HTTPBasicAuth

def encrypt_rsa(message, header, public_key_pem):
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

    url = "http://singlepot1/pub_key"
    payload = {"key": "abc"}

    public_key_pem = ""

    try:
        response = requests.post(url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})
        response_data = response.json()  # Parsowanie odpowiedzi JSON

    # Sprawdź, czy istnieje klucz publiczny w odpowiedzi
        if "key" in response_data:
            public_key_pem_decoded = response_data["key"]
            print("Klucz publiczny:", public_key_pem)
            public_key_pem = response_data["key"].encode('utf-8')
        else:
            print("Błąd: Brak klucza publicznego w odpowiedzi serwera.")

    except requests.exceptions.RequestException as e:
        print("Błąd podczas wysyłania żądania:", e)

    # Przykładowy klucz publiczny w formacie PEM
    #public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJdkRkdrzES5oz4/2T8o\nLetb9EEcfWt5gywCFvOGpLa3HjBX2NTbgBj7bRiY4CKVOlMJUk9xyw6knc4rCiyb\nLslKtxdOUJ+5tdTxsDm04HHdQ/bhPfRQ8xEVmSOLaP7kXQfmeFbwuSP/TWGnm7hy\nzXgAjDFivX4taY2pKK5EG4OwJk3xiOaCd1788VTnAQK7eEdkonjmd82hULqC2cMy\nC3bbb0/dSxEvan3JmGAsxjQsNWsnbDtDtg9vBirosMINLF/d/cLLd94ozB/cO0g7\nZC4tnwW/vg0nsk7loSpKDVOqwwWF4WHigIo3GuNCqXEqW1MTZBxtKd2XFjjzarrX\n1wIDAQAB\n-----END PUBLIC KEY-----\n"

    # Zaszyfruj wiadomość przy użyciu klucza publicznego

    payload = {"material": message_to_encrypt}
    json_payload = json.dumps(payload)

    username = "singlepotuser"
    password = "Vfd23m*nr=vPgGJ"
    credentials = f"{username}:{password}"

    base64_encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')

    head = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {base64_encoded_credentials}',
        'UUID': "b662e4e9"
    }

    if public_key_pem:
        encrypted_message = encrypt_rsa(json_payload, head, public_key_pem)

    # Wyświetl zaszyfrowaną wiadomość
        print("Zaszyfrowana wiadomość:", encrypted_message.hex())

    # Wyślij żądanie HTTP
        url = "http://singlepot1/encode_test"
        # payload = {"material": encrypted_message.hex()}

        time.sleep(5)
        try:
            response = requests.post(url, data=encrypted_message, headers=head)
            print("Kod odpowiedzi serwera:", response.status_code)
            print("Odpowiedź serwera:", response.text)
        except requests.exceptions.RequestException as e:
            print("Błąd podczas wysyłania żądania:", e)
    else:
        print("klucz publiczny pusty")
