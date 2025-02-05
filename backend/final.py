import os
import cv2
import numpy as np
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256


def generate_key(location, keyword, date, time):
    key_data = f"{location}_{keyword}_{date}_{time}"
    return sha256(key_data.encode()).digest()


def encrypt_message(message, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + encrypted_message).decode()


def hide_message_in_image(image_path, message, output_path, location, keyword, date, time):
    key = generate_key(location, keyword, date, time)
    encrypted_message = encrypt_message(message, key)

    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError("Invalid image path or unsupported format")

    height, width, _ = img.shape
    max_bytes = (height * width * 3) // 8

    if len(encrypted_message) > max_bytes:
        raise ValueError("Message is too large to hide in image")

    encrypted_message += "###"
    binary_message = ''.join(format(ord(c), '08b') for c in encrypted_message)
    binary_message += '0' * ((8 - len(binary_message) % 8) % 8)

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
    return key


def extract_message_from_image(image_path, location, keyword, date, time):
    key = generate_key(location, keyword, date, time)

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
        decoded_data = base64.b64decode(extracted_message + "==")  # Ensure valid padding
        iv, tag, encrypted_message = decoded_data[:12], decoded_data[12:28], decoded_data[28:]
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
        date = input("Enter date (DD-MM-YYYY): ").strip()
        time = input("Enter time (HH:MM) in 24-hour format: ").strip()

        try:
            hide_message_in_image(image_path, message, output_path, location, keyword, date, time)
            print("Message successfully hidden in image!")
        except Exception as e:
            print(f"[ERROR] {str(e)}")

    elif choice == "D":
        image_path = input("Enter path of the image: ").strip()
        location = input("Enter location used for encryption: ").strip()
        keyword = input("Enter keyword used for encryption: ").strip()
        date = input("Enter date used for encryption (DD-MM-YYYY): ").strip()
        time = input("Enter time used for encryption (HH:MM) in 24-hour format: ").strip()

        try:
            decrypted_message = extract_message_from_image(image_path, location, keyword, date, time)
            print(f"Decrypted Message: {decrypted_message}")
        except Exception as e:
            print(f"[ERROR] {str(e)}")
