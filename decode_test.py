from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import requests
import json
import time
import base64
from requests.auth import HTTPBasicAuth

# Przykład użycia:
if __name__ == "__main__":

    url = "http://singlepot1/pub_key"
    
    # Tutaj dodaj kod do generowania klucza publicznego i zapisz go do zmiennej public_key_pem

    # Na przykład:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    payload = {"key": public_key_pem}

    try:
        response = requests.post(url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})
        print("Kod odpowiedzi serwera:", response.status_code)
        response_data = response.json()  # Parsowanie odpowiedzi JSON
        

        # Sprawdź, czy istnieje klucz publiczny w odpowiedzi
        if "key" in response_data:
            public_key_pem_decoded = response_data["key"]
            print("Klucz publiczny:", public_key_pem_decoded)
            public_key_pem = public_key_pem_decoded.encode('utf-8')
        else:
            print("Błąd: Brak klucza publicznego w odpowiedzi serwera.")

    except requests.exceptions.RequestException as e:
        print("Błąd podczas wysyłania żądania:", e)

    time.sleep(5)

    payload = {"material": "decode_test"}
    url = "http://singlepot1/decode_test"
    try:
        response = requests.post(url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})
        print("Kod odpowiedzi serwera:", response.status_code)
        print("Odpowiedź: ", response.content)
        encrypted_message_hex = response.content.decode('utf-8')
        encrypted_message = bytes.fromhex(encrypted_message_hex)
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode('utf-8')
        print("Odszyfrowana wiadomość:", decrypted_message)
        response_data = json.loads(decrypted_message)
        if "odp" in response_data:
            odp = response_data["odp"]
            print("odp:", odp)
        else:
            print("Błąd: Brak odp w odpowiedzi serwera.")
    except requests.exceptions.RequestException as e:
        print("Błąd podczas wysyłania żądania:", e)