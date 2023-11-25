from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import requests
import json
import time
import base64
from requests.auth import HTTPBasicAuth

def ret_haeders(uuid):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {base64_encoded_credentials}',
        'UUID': uuid
    }

    return headers

def encrypt_rsa(message, public_key_pem):
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

if __name__ == "__main__":

    username = "singlepotuser"
    password = "Vfd23m*nr=vPgGJ"
    credentials = f"{username}:{password}"

    base64_encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')

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

    print("Klucz publiczny klienta:\n", public_key_pem)

    payload = {"key": public_key_pem}

    try:
        response = requests.post(url, data=json.dumps(payload), headers=ret_haeders("1234"))
        print("Kod odpowiedzi serwera:", response.status_code)
        response_data = response.json()  # Parsowanie odpowiedzi JSON
        

        # Sprawdź, czy istnieje klucz publiczny w odpowiedzi
        if "key" in response_data:
            public_key_pem_decoded = response_data["key"]
            print("Klucz publiczny donicy:\n", public_key_pem_decoded)
            public_key_pem = public_key_pem_decoded.encode('utf-8')
        else:
            print("Błąd: Brak klucza publicznego w odpowiedzi serwera.")

    except requests.exceptions.RequestException as e:
        print("Błąd podczas wysyłania żądania:", e)

    # time.sleep(4)
    
    # url = "http://singlepot1/get_soil_moisture"
    # try:
    #     response = requests.get(url, headers=ret_haeders("1234"))
    #     print("Kod odpowiedzi serwera:", response.status_code)
    #     print("Zaszyfrowana odpowiedź: ", response.content)
    #     encrypted_message_hex = response.content.decode('utf-8')
    #     encrypted_message = bytes.fromhex(encrypted_message_hex)
    #     decrypted_message = private_key.decrypt(
    #         encrypted_message,
    #         padding.OAEP(
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     ).decode('utf-8')
    #     print("Odszyfrowana odpowiedź: ", decrypted_message)
    # except requests.exceptions.RequestException as e:
    #     print("Błąd podczas wysyłania żądania:", e)

    # time.sleep(4)

    # url = "http://singlepot1/get_water_level"
    # try:
    #     response = requests.get(url, headers=ret_haeders("1234"))
    #     print("Kod odpowiedzi serwera:", response.status_code)
    #     print("Zaszyfrowana odpowiedź: ", response.content)
    #     encrypted_message_hex = response.content.decode('utf-8')
    #     encrypted_message = bytes.fromhex(encrypted_message_hex)
    #     decrypted_message = private_key.decrypt(
    #         encrypted_message,
    #         padding.OAEP(
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     ).decode('utf-8')
    #     print("Odszyfrowana odpowiedź: ", decrypted_message)
    # except requests.exceptions.RequestException as e:
    #     print("Błąd podczas wysyłania żądania:", e)


    # time.sleep(4)

    # url = "http://singlepot1/set_watering"
    # try:
    #     response = requests.get(url, headers=ret_haeders("1234"))
    #     print("Kod odpowiedzi serwera:", response.status_code)
    #     print("Zaszyfrowana odpowiedź: ", response.content)
    #     encrypted_message_hex = response.content.decode('utf-8')
    #     encrypted_message = bytes.fromhex(encrypted_message_hex)
    #     decrypted_message = private_key.decrypt(
    #         encrypted_message,
    #         padding.OAEP(
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     ).decode('utf-8')
    #     print("Odszyfrowana odpowiedź: ", decrypted_message)
    # except requests.exceptions.RequestException as e:
    #     print("Błąd podczas wysyłania żądania:", e)

    # time.sleep(4)

    # url = "http://singlepot1/set_watering_settings"
    # try:
    #     response = requests.get(url, headers=ret_haeders("1234"))
    #     print("Kod odpowiedzi serwera:", response.status_code)
    #     print("Zaszyfrowana odpowiedź: ", response.content)
    #     encrypted_message_hex = response.content.decode('utf-8')
    #     encrypted_message = bytes.fromhex(encrypted_message_hex)
    #     decrypted_message = private_key.decrypt(
    #         encrypted_message,
    #         padding.OAEP(
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     ).decode('utf-8')
    #     print("Odszyfrowana odpowiedź: ", decrypted_message)
    # except requests.exceptions.RequestException as e:
    #     print("Błąd podczas wysyłania żądania:", e)

    # time.sleep(4)

    # payload = {"watering": "OFF"}
    # json_payload = json.dumps(payload)
    # print("Wysyłane dane przed zaszyfrowaniem: ", json_payload)

    # if public_key_pem:
    #     encrypted_message = encrypt_rsa(json_payload, public_key_pem)
    #     print("Zaszyfrowana wiadomość:", encrypted_message.hex())

    # # Wyślij żądanie HTTP
    #     url = "http://singlepot1/set_watering"

    #     try:
    #         response = requests.post(url, data=encrypted_message, headers=ret_haeders("1234"))
    #         print("Kod odpowiedzi serwera:", response.status_code)
    #     except requests.exceptions.RequestException as e:
    #         print("Błąd podczas wysyłania żądania:", e)
    # else:
    #     print("Klucz publiczny pusty")


    # time.sleep(4)

    # payload = {"moisture_max":60,"moisture_min":10,"watering_time":"12:00","watering_max_time":31}
    # json_payload = json.dumps(payload)
    # print("Wysyłane dane przed zaszyfrowaniem: ", json_payload)

    # if public_key_pem:
    #     encrypted_message = encrypt_rsa(json_payload, public_key_pem)
    #     print("Zaszyfrowana wiadomość:", encrypted_message.hex())

    # # Wyślij żądanie HTTP
    #     url = "http://singlepot1/set_watering_settings"

    #     try:
    #         response = requests.post(url, data=encrypted_message, headers=ret_haeders("1234"))
    #         print("Kod odpowiedzi serwera:", response.status_code)
    #     except requests.exceptions.RequestException as e:
    #         print("Błąd podczas wysyłania żądania:", e)
    # else:
    #     print("Klucz publiczny pusty")


    time.sleep(4)

    payload = {"cred1":"singlepotuser", "cred2": "Vfd23m*nr=vPgGJ"}
    json_payload = json.dumps(payload)
    print("Wysyłane dane przed zaszyfrowaniem: ", json_payload)

    if public_key_pem:
        encrypted_message = encrypt_rsa(json_payload, public_key_pem)
        print("Zaszyfrowana wiadomość:", encrypted_message.hex())

    # Wyślij żądanie HTTP
        url = "http://singlepot1/change_pass"

        try:
            response = requests.post(url, data=encrypted_message, headers=ret_haeders("1234"))
            print("Kod odpowiedzi serwera:", response.status_code)
        except requests.exceptions.RequestException as e:
            print("Błąd podczas wysyłania żądania:", e)
    else:
        print("Klucz publiczny pusty")