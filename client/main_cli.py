import os
import getpass
import json
import base64
from client.core.crypto import CryptoEngine
from client.core.storage import LocalVaultStorage
from client.network.scanner import NetworkScanner
from client.core.waf_middleware import InputSanitizer  # Import WAF Engine

vault_path = os.environ.get('VAULT_FILE_PATH', 'vault.json')

def run_station():
    scanner = NetworkScanner()
    sanitizer = InputSanitizer()  
    
    if not os.path.exists(vault_path):
        print("Creating a new local security profile.")
        master_pw = getpass.getpass("Set your Master Password: ")
        crypto = CryptoEngine(master_pw)
        
        live_devices = scanner.parse_results(scanner.scan_network())
        scanner.authorized_macs = list(live_devices.values())
        is_safe = True
        
    else:
        with open(vault_path, 'r') as file:
            content = json.load(file)
            salt = content["salt"]
            decoded_salt = base64.b64decode(salt)
            saved_macs = content.get("authorized_macs", [])
            
        pw = getpass.getpass("Enter Master Password to unlock: ")
        crypto = CryptoEngine(pw, decoded_salt)
        
        scanner.authorized_macs = saved_macs
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
            raw_site = input("Enter website/service domain: ")
            raw_user = input("Enter username: ")
            raw_pass = input("Enter password: ")

            site_name = sanitizer.sanitize_string(raw_site)
            username = sanitizer.sanitize_string(raw_user)
            password = sanitizer.sanitize_string(raw_pass)

            storage.add_entry(site_name, username, password)
            print("Successful profile creation.")

        elif choice == "2":
            site_name = input("Enter the website/service name to retrieve: ")
            if site_name in storage.entries:
                account_info = storage.entries[site_name]
                print(f"-> Username: {account_info['user']}")
                print(f"-> Password: {account_info['pass']}")
            else:
                print("No matching service name found.")
                
        elif choice == "3":
            print("Session safely closed. Goodbye!")
            break

if __name__ == "__main__":
    run_station()