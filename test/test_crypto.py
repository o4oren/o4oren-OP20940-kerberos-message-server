import unittest

from common.cryptography_utils import encrypt_aes_cbc, decrypt_aes_cbc, generate_aes_key


class CryptoTest(unittest.TestCase):
    def test_encryption_decryption(self):
        key = generate_aes_key()
        text_bytes = 'my encrypted text'.encode()

        encrypted, iv = encrypt_aes_cbc(key, text_bytes, None)
        self.assertNotEqual(text_bytes, encrypted)

        decrypted = decrypt_aes_cbc(key, encrypted, iv)

        print(f'decrypted: {decrypted.decode()}!')
        self.assertEqual(text_bytes, decrypted)


if __name__ == '__main__':
    unittest.main()
