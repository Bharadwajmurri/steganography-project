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


def apply_dct(image):
    image = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb)
    dct = np.zeros_like(image, dtype=np.float32)
    for i in range(3):
        dct[:, :, i] = cv2.dct(np.float32(image[:, :, i]))
    return dct


def inverse_dct(dct):
    image = np.zeros_like(dct, dtype=np.uint8)
    for i in range(3):
        image[:, :, i] = cv2.idct(dct[:, :, i])
    return cv2.cvtColor(image, cv2.COLOR_YCrCb2BGR)


def hide_message_in_image(image_path, message, output_path, location, keyword, date, time):
    key = generate_key(location, keyword, date, time)
    encrypted_message = encrypt_message(message, key)

    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError("Invalid image path or unsupported format")

    dct_image = apply_dct(img)
    message_bin = ''.join(format(ord(c), '08b') for c in encrypted_message) + '11111111'

    idx = 0
    for i in range(0, dct_image.shape[0], 8):
        for j in range(0, dct_image.shape[1], 8):
            if idx < len(message_bin):
                dct_image[i, j, 0] += int(message_bin[idx])
                idx += 1

    stego_image = inverse_dct(dct_image)
    cv2.imwrite(output_path, stego_image, [cv2.IMWRITE_JPEG_QUALITY, 100])
    return key


def extract_message_from_image(image_path, location, keyword, date, time):
    key = generate_key(location, keyword, date, time)

    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError("Invalid image path or unsupported format")

    dct_image = apply_dct(img)
    binary_message = ""
    for i in range(0, dct_image.shape[0], 8):
        for j in range(0, dct_image.shape[1], 8):
            binary_message += str(int(dct_image[i, j, 0]) & 1)

    byte_chunks = [binary_message[i:i + 8] for i in range(0, len(binary_message), 8)]
    extracted_message = ''.join(chr(int(b, 2)) for b in byte_chunks if b != '11111111')

    try:
        decoded_data = base64.b64decode(extracted_message + "==")
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
