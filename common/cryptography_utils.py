from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64


def encrypt_aes_cbc(key, plaintext, iv):
    """
    Encrypts a text with the given key using AES-CBC
    :param key: The encryption key bytes
    :param plaintext: The text string to encrypt
    :param iv: an iv byte array to start the encryption with. In None, a random iv will be generated
    :return: A tuple of the encrypted text and the iv encoded as base64 uft-8
    """
    # Generate a random IV (Initialization Vector)
    if iv is None:
        iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext), base64.b64encode(iv)


def decrypt_aes_cbc(key, encrypted_text, iv):
    """
    Decrypts an AES-CBC encoded text
    :param key: The key bytes
    :param encrypted_text: Base64 encoded encrypted text
    :param iv: Base64 encoded iv
    :return: plain text bytes
    """
    try:
        iv = base64.b64decode(iv)
        ct = base64.b64decode(encrypted_text)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ct), AES.block_size)
        return plaintext
    except (ValueError, KeyError):
        print("Incorrect decryption")
    return None


def sha256_hash(input_bytes: bytes):
    # Create a new SHA-256 hash object
    sha256_hash_object = SHA256.new()

    # Update the hash object with the bytes representation of the input string
    sha256_hash_object.update(input_bytes)

    hashed_bytes = sha256_hash_object.digest()

    return hashed_bytes


def generate_aes_key():
    key = get_random_bytes(32)
    return key
