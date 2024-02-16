import unittest

from common.cryptography_utils import encrypt_aes_cbc, decrypt_aes_cbc


class CryptoTest(unittest.TestCase):
    def test_encryption_decryption(self):
        key = 'abcdabcdabcdabcd'.encode()
        text = 'my encrypted text'.encode()

        encrypted, iv = encrypt_aes_cbc(key, text, None)
        self.assertNotEqual(bytes(text), encrypted)

        decrypted = decrypt_aes_cbc(key, encrypted, iv)

        print(f'decrypted: {decrypted}!')
        self.assertEqual(bytes(text), decrypted)


if __name__ == '__main__':
    unittest.main()
