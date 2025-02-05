from Crypto.Cipher import AES
import base64
import numpy as np
import hashlib
from Crypto.Protocol.KDF import PBKDF2
import time
import cv2
import scipy.fftpack


def generate_key(location, keyword, timestamp):
    combined_input = location + keyword + timestamp
    salt = b"unique_salt_for_security"
    key = PBKDF2(combined_input.encode(), salt, dkLen=16, count=1000000)
    return key


def extract_encrypted_message(image_path):
    img = cv2.imread(image_path, cv2.IMREAD_COLOR)
    img = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
    Y, Cr, Cb = cv2.split(img)

    Y_dct = scipy.fftpack.dct(scipy.fftpack.dct(Y.T, norm='ortho').T, norm='ortho')

    message_bits = ''
    for i in range(Y_dct.shape[0]):
        for j in range(Y_dct.shape[1]):
            message_bits += '1' if Y_dct[i, j] > 0 else '0'

    try:
        extracted_bytes = [int(message_bits[i:i + 8], 2) for i in range(0, len(message_bits), 8)]
        extracted_bytes = bytes(extracted_bytes)
        encrypted_message = extracted_bytes.decode('utf-8', errors='ignore')
        return encrypted_message.strip('\x00')
    except Exception as e:
        print("[ERROR] Message extraction failed:", e)
        return ""


def decrypt_message(encrypted_message, key):
    try:
        encrypted_data = base64.b64decode(encrypted_message.encode())
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode()
        return decrypted_message
    except Exception as e:
        print("[ERROR] Decryption failed:", e)
        return ""


if __name__ == "__main__":
    image_path = input("Enter path of image to extract message: ")
    location = input("Enter location used for encryption: ")
    keyword = input("Enter keyword used for encryption: ")
    timestamp = input("Enter timestamp used for encryption: ")

    encrypted_message = extract_encrypted_message(image_path)
    if encrypted_message:
        key_used = generate_key(location, keyword, timestamp)
        decrypted_message = decrypt_message(encrypted_message, key_used)
        if decrypted_message:
            print("[SUCCESS] Decrypted message:", decrypted_message)
        else:
            print("[ERROR] Decryption failed.")