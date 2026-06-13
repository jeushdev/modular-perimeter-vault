import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CryptoEngine:
    def __init__(self, master_password: str, salt: bytes = None):
        self.salt = salt if salt is not None else os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            iterations=600000,
            salt=self.salt
        )
        
        self._derived_key = kdf.derive(master_password.encode('utf-8'))

    def encrypt(self, plain_text: str) -> dict:
        nonce = os.urandom(12)

        encryptor = Cipher(
            algorithms.AES(self._derived_key),
            modes.GCM(nonce)
        ).encryptor()

        ciphertext = encryptor.update(plain_text.encode('utf-8')) + encryptor.finalize()
        
        tag = encryptor.tag

        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag
        }

    def decrypt(self, encrypted_data: dict) -> str:
        ciphertext = encrypted_data["ciphertext"]
        nonce = encrypted_data["nonce"]
        tag = encrypted_data["tag"]

        decryptor = Cipher(
            algorithms.AES(self._derived_key),
            modes.GCM(nonce, tag)
        ).decryptor()

        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_bytes.decode('utf-8')