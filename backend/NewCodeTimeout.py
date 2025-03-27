import os
import cv2
import numpy as np
import base64
import time
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

# Constants
DEFAULT_TTL = 600  # 10 minutes


def generate_key(location, keyword):
    key_data = f"{location}_{keyword}"
    return sha256(key_data.encode()).digest()


def encrypt_message(message, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return iv, encryptor.tag, base64.b64encode(encrypted_message).decode()


def hide_message_in_image(image_path, message, output_path, location, keyword, ttl=DEFAULT_TTL):
    key = generate_key(location, keyword)
    iv, tag, encrypted_message = encrypt_message(message, key)
    timestamp = int(time.time())

    # Pack data into a JSON string
    data = base64.b64encode(
        json.dumps({
            'iv': base64.b64encode(iv).decode(),
            'tag': base64.b64encode(tag).decode(),
            'msg': encrypted_message,
            'timestamp': timestamp,
            'ttl': ttl
        }).encode()
    ).decode() + '###'

    # LSB Encoding
    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError("Invalid image path or unsupported format")

    height, width, _ = img.shape
    max_bytes = (height * width * 3) // 8

    if len(data) > max_bytes:
        raise ValueError("Message is too large to hide in image")

    binary_message = ''.join(format(ord(c), '08b') for c in data)
    data_index = 0

    for row in img:
        for pixel in row:
            for channel in range(len(pixel)):
                if data_index < len(binary_message):
                    pixel[channel] = (pixel[channel] & 0xFE) | int(binary_message[data_index])
                    data_index += 1
                else:
                    break

    cv2.imwrite(output_path, img)
    print("Message successfully hidden in image!")


def extract_message_from_image(image_path, location, keyword):
    key = generate_key(location, keyword)

    # LSB Decoding
    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError("Invalid image path or unsupported format")

    binary_data = ""
    for row in img:
        for pixel in row:
            for channel in range(len(pixel)):
                binary_data += str(pixel[channel] & 1)

    bytes_data = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
    extracted_message = ''.join(chr(int(b, 2)) for b in bytes_data if int(b, 2) != 0)
    extracted_message = extracted_message.split("###")[0]

    try:
        decoded_data = json.loads(base64.b64decode(extracted_message).decode())
        iv = base64.b64decode(decoded_data['iv'])
        tag = base64.b64decode(decoded_data['tag'])
        encrypted_message = base64.b64decode(decoded_data['msg'])
        timestamp = decoded_data['timestamp']
        ttl = decoded_data['ttl']

        # Check for timeout
        current_time = int(time.time())
        if current_time > timestamp + ttl:
            return "[ERROR] Session Expired: Time limit exceeded."

        # Decrypt message
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        return decrypted_message.decode()
    except Exception as e:
        return f"[ERROR] Decryption failed: {str(e)}"


if __name__ == "__main__":
    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ").strip().upper()

    if choice == "E":
        image_path = input("Enter path of the image: ").strip()
        message = input("Enter the message to hide: ").strip()
        output_path = input("Enter output image path (with extension): ").strip()
        location = input("Enter location: ").strip()
        keyword = input("Enter keyword: ").strip()

        try:
            hide_message_in_image(image_path, message, output_path, location, keyword)
        except Exception as e:
            print(f"[ERROR] {str(e)}")

    elif choice == "D":
        image_path = input("Enter path of the image: ").strip()
        location = input("Enter location used for encryption: ").strip()
        keyword = input("Enter keyword used for encryption: ").strip()

        try:
            decrypted_message = extract_message_from_image(image_path, location, keyword)
            print(f"Decrypted Message: {decrypted_message}")
        except Exception as e:
            print(f"[ERROR] {str(e)}")
