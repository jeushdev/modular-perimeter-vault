import os, json, base64
from client.core.crypto import CryptoEngine

class LocalVaultStorage:
    def __init__(self, file_path: str, crypto_engine: CryptoEngine):
        self.entries = {}
        self.file_path = file_path
        self.crypto = crypto_engine
        self.load()

    def save(self):
        flat_string = json.dumps(self.entries)
        encrypted_payload = self.crypto.encrypt(flat_string)

        safe_text = {
            "text" : base64.b64encode(encrypted_payload["ciphertext"]).decode('utf-8'),
            "nonce" : base64.b64encode(encrypted_payload["nonce"]).decode('utf-8'),
            "tag" : base64.b64encode(encrypted_payload["tag"]).decode('utf-8'),
            "salt" : base64.b64encode(self.crypto.salt).decode('utf-8')
        }

        with open(self.file_path, 'w') as file:
            json.dump(safe_text, file)


    def load(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as file:
                loaded_text = json.load(file)
            
            decoded_ciphertext = base64.b64decode(loaded_text["text"])
            decoded_nonce = base64.b64decode(loaded_text["nonce"])
            decoded_tag = base64.b64decode(loaded_text["tag"])

            clean_dictionary = {
                "ciphertext" : decoded_ciphertext,
                "nonce": decoded_nonce,
                "tag" : decoded_tag
            }

            flat_string = self.crypto.decrypt(clean_dictionary)

            self.entries = json.loads(flat_string)
        else:
            return

    def add_entry(self, site_name: str, username: str, secret: str):
        # 1. Update your live memory dictionary
        self.entries[site_name] = {"user": username, "pass": secret}
        # 2. Immediately persist changes to disk
        self.save()