from Crypto.Cipher import AES
import base64
from PIL import Image
import stepic

# Function to decrypt the extracted message
def decrypt_message(encrypted_data, key):
    try:
        raw_data = base64.b64decode(encrypted_data)
        nonce = raw_data[:16]
        tag = raw_data[16:32]
        ciphertext = raw_data[32:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_message.decode()
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# Function to extract and decrypt message from an image
def extract_message_from_image(image_path, key):
    img = Image.open(image_path)
    encrypted_message = stepic.decode(img)

    decrypted_message = decrypt_message(encrypted_message, key)
    return decrypted_message

# User Input
image_path = input("Enter the path of the image: ")
key_hex = input("Enter the encryption key: ")
key = bytes.fromhex(key_hex)

# Extract and decrypt message
retrieved_message = extract_message_from_image(image_path, key)
print("Decrypted Message:", retrieved_message)
