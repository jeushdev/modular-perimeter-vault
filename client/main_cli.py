import os, getpass, json, base64
from core.crypto import CryptoEngine
from core.storage import LocalVaultStorage

vault_path = os.environ.get('VAULT_FILE_PATH','vault.json')

def run_station():
    if not os.path.exists(vault_path):
        print("Creating a new local security profile.")
        master_pw = getpass.getpass()
        crypto = CryptoEngine(master_pw)
    else:
        with open(vault_path, 'r') as file:
            content = json.load(file)
            salt = content["salt"]
            decoded_salt = base64.b64decode(salt)
            pw = getpass.getpass()
            crypto = CryptoEngine(pw, decoded_salt)

    storage = LocalVaultStorage(vault_path, crypto)

    while True:
        print("[1] Store New Password Entry")
        print("[2] Retrieve Password Profile Lookup")
        print("[3] Safe Station Disconnect")

        choice = input("Enter your choice: ")

        if choice == "1":
            site_name = str(input("Enter the website name/service name of this profile: "))
            username = str(input("Enter profile username: "))
            password = str(input("Enter profile password: "))

            storage.add_entry(site_name, username, password)
            
            print("Succesful profile creation.")

        elif choice == "2":
            site_name = str(input("Enter the website name/service name you want to retrieve: "))
            if site_name in storage.entries:
                account_info = storage.entries[site_name]
                print(f"The username for this profile is {account_info['user']}.")
                print(f"The password for this profile is {account_info['pass']}.")
            else:
                print("No matching service name found.")
        elif choice == "3":
            print("Session safely closed.")
            break