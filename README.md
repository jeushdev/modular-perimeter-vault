# advanced-perimeter-vault-and-waf

> Local Zero-Trust Security Station & WAF Ingestion Suite engineered from scratch in pure Python.  
> Combines an authenticated AES-256-GCM client-side vault, a Layer 2 wireless perimeter watchdog, and inline WAF input normalization filters.

---

## What it does

- **Zero-Knowledge Storage:** Authenticates, derives, and encrypts credentials completely client-side in volatile memory before disk persistence.
- **Layer 7 Input Normalization:** Ingests raw terminal strings through an object-oriented WAF middleware to strip SQLi and XSS payloads at birth.
- **Layer 2 Perimeter Watchdog:** Executes dynamic multi-OS ARP table sweeps to detect rogue neighborhood network sniffers and pivot attacks.
- **Containment System Lock:** Traps low-level cryptographic errors natively, freezing the interface instantly if a wrong password or untrusted MAC is flagged.

## Architecture

Designed strictly around decoupled SOLID principles. All operational modules—the cryptographic core, the storage manager, the WAF middleware, and the network scanner—are isolated classes bound dynamically at runtime via constructor dependency injection. 


```

[ User Input ] ──► [ Layer 7 WAF Middleware ] ──► [ PBKDF2 / AES-256-GCM ] ──► [ Authenticated JSON Store ]
▲
(Layer 2 Whitelist Guard)

```

## Stack

| Layer | Technology / Implementation |
|---|---|
| **Cryptographic Core** | Python Primitives (`cryptography` library), AES-256-GCM |
| **Key Derivation** | PBKDF2HMAC-SHA256, 100,000 Iterations, 16-byte Cryptographic Salt |
| **Network Discovery** | Native OS Subprocess Pipes (`win32` / `linux` / `darwin` ARP parsing) |
| **Input Sanitization** | Regular Expression Compile Engines (`re`), HTML Bracket Escaping |
| **Error Containment** | Low-Level Cryptographic Signal Trapping (`InvalidTag`, `ValueError`) |

## Run it

Ensure you have your environment variables set up using your local configuration reference map before initializing.

```bash
# 1. Clone the repository workspace
git clone [https://github.com/jeushdev/advanced-perimeter-vault-and-waf](https://github.com/jeushdev/advanced-perimeter-vault-and-waf)
cd advanced-perimeter-vault-and-waf

# 2. Install local cryptographic dependencies
pip install cryptography

# 3. Boot the main pre-flight gateway controller loop
python client/main_cli.py

```

## Adversarial Perimeter Testing

1. Initialize a fresh `vault.json` database profile on your home subnet to automatically white-list your trusted base hardware signatures.
2. Open `client/main_cli.py` and manually overwrite the scanner's whitelist memory registry with an unmapped adversarial address:
```python
scanner.authorized_macs = ["00:00:00:00:00:00"]

```

3. Re-launch the application. The system integrity sweep will intercept the anomaly, drop uninitialized variables from RAM, and enforce an immediate security lockout:
```text
!!! SECURITY ALERT: UNREGISTERED MAC ADDRESS DETECTED ON THIS NETWORK !!!
Application locked down to prevent potential credential sniffing.

```

## Why I built this

Most people assume local applications don't need network security or input sanitization. I engineered this to prove the value of a true Defense-in-Depth posture—showing how client-side processing must protect its input boundary against second-order cloud attacks, while continuously validating the physical environment it is running on.

## 👤 Author

* **Jeush Samuel L. Bantayaon** - Computer Science Student
* **Connect:** https://www.linkedin.com/in/jeush-samuel-bantayaon-2ab40b370/

```
