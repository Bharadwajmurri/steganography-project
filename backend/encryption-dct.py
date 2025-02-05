from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from PIL import Image
import numpy as np
import hashlib
from Crypto.Protocol.KDF import PBKDF2
import time
import os
import cv2
import scipy.fftpack


def generate_key(location, keyword, timestamp):
    combined_input = location + keyword + timestamp
    salt = b"unique_salt_for_security"
    key = PBKDF2(combined_input.encode(), salt, dkLen=16, count=1000000)
    return key


def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    encrypted_data = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    return encrypted_data


def hide_message_in_image(image_path, message, output_path, location, keyword, timestamp):
    key = generate_key(location, keyword, timestamp)
    encrypted_message = encrypt_message(message, key)

    img = cv2.imread(image_path, cv2.IMREAD_COLOR)
    img = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
    Y, Cr, Cb = cv2.split(img)

    Y_dct = scipy.fftpack.dct(scipy.fftpack.dct(Y.T, norm='ortho').T, norm='ortho')
    message_bits = ''.join(format(ord(char), '08b') for char in encrypted_message)

    idx = 0
    for i in range(Y_dct.shape[0]):
        for j in range(Y_dct.shape[1]):
            if idx < len(message_bits):
                Y_dct[i, j] = Y_dct[i, j] + (1 if message_bits[idx] == '1' else -1)
                idx += 1
            else:
                break

    Y_idct = scipy.fftpack.idct(scipy.fftpack.idct(Y_dct.T, norm='ortho').T, norm='ortho')
    Y_idct = np.clip(Y_idct, 0, 255)

    stego_img = cv2.merge((Y_idct.astype(np.uint8), Cr, Cb))
    stego_img = cv2.cvtColor(stego_img, cv2.COLOR_YCrCb2BGR)
    cv2.imwrite(output_path, stego_img)

    print(f"[SUCCESS] Encrypted message hidden in: {output_path}")
    print("[INFO] Use this timestamp for decryption:", timestamp)


if __name__ == "__main__":
    image_path = input("Enter image path: ")
    message = input("Enter secret message: ")
    location = input("Enter location: ")
    keyword = input("Enter keyword: ")
    timestamp = str(time.time())
    output_path = "output_image.jpg"

    hide_message_in_image(image_path, message, output_path, location, keyword, timestamp)