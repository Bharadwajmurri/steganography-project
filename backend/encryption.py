from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from PIL import Image
import stepic


# Function to convert any image to PNG
def convert_to_png(image_path):
    img = Image.open(image_path)
    output_path = image_path.rsplit(".", 1)[0] + ".png"  # Convert filename to .png
    img.convert("RGBA").save(output_path, "PNG")
    return output_path


# Function to encrypt text using AES-GCM
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    encrypted_data = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    return encrypted_data


# Function to hide encrypted message in an image
def hide_message_in_image(image_path, message, output_path):
    key = get_random_bytes(16)  # AES-128 bit key

    # Convert any image format to PNG
    image_path = convert_to_png(image_path)

    encrypted_message = encrypt_message(message, key)

    img = Image.open(image_path)
    img_with_message = stepic.encode(img, encrypted_message.encode())

    img_with_message.save(output_path, "PNG")

    print(f"Message successfully hidden in {output_path}")
    print("Encryption Key (Save this securely):", key.hex())
    return key  # Return key for decryption


# User Input
image_path = input("Enter the path of the image: ")
message = input("Enter the secret message: ")
output_path = "output_image.png"  # You can modify this

# Encrypt and embed message
key_used = hide_message_in_image(image_path, message, output_path)
