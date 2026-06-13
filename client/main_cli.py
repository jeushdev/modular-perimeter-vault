import os, getpass, json, base64
from core.crypto import CryptoEngine
from core.storage import LocalVaultStorage
from network.scanner import NetworkScanner

vault_path = os.environ.get('VAULT_FILE_PATH','vault.json')

def run_station():
    scanner = NetworkScanner()

    if not os.path.exists(vault_path):
        print("Creating a new local security profile.")
        master_pw = getpass.getpass()
        crypto = CryptoEngine(master_pw)
        live_devices = scanner.parse_results(scanner.scan_network())
        is_safe = True
        scanner.authorized_macs = list(live_devices.values())
    else:
        with open(vault_path, 'r') as file:
            content = json.load(file)
            salt = content["salt"]
            decoded_salt = base64.b64decode(salt)
            saved_macs = content.get("authorized_macs", [])
        pw = getpass.getpass()
        crypto = CryptoEngine(pw, decoded_salt)
        scanner.authorized_macs = content["authorized_macs"]
        live_devices = scanner.parse_results(scanner.scan_network())
        is_safe = scanner.verify_parameters(live_devices)

    if not is_safe:
        print("\n!!! SECURITY ALERT: UNREGISTERED MAC ADDRESS DETECTED ON THIS NETWORK !!!")
        print("Application locked down to prevent potential credential sniffing.")
        return
    else:
        print("Local Area Network validated. Environment secure.")

    storage = LocalVaultStorage(vault_path, crypto, scanner.authorized_macs)

    if not os.path.exists(vault_path):
        storage.save()

    while True:
        print("\n=== LIFESTYLE SECURITY STATION ===")
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
if __name__ == "__main__":
    run_station()