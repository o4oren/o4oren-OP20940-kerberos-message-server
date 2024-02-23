import secrets
import traceback

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def encrypt_aes_cbc(key, plain_bytes, iv):
    """
    Encrypts a text with the given key using AES-CBC
    :param key: The encryption key bytes
    :param plain_bytes: The bytes to encrypt
    :param iv: an iv byte array to start the encryption with. In None, a random iv will be generated
    :return: A tuple of the encrypted bytes and the iv bytes
    """
    # Generate a random IV (Initialization Vector)
    if iv is None:
        iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plain_bytes, AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    return encrypted_bytes, iv


def decrypt_aes_cbc(key, encrypted_bytes, iv):
    """
    Decrypts an AES-CBC encoded text
    :param key: The key bytes
    :param encrypted_bytes: encrypted bytes
    :param iv: iv bytes
    :return: decrypted bytes
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
    return decrypted_bytes

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


def generate_nonce_bytes():
    byte_size = 8
    random_bytes = secrets.token_bytes(byte_size)
    return random_bytes
