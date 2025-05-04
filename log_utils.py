import hashlib
import json
import os
from cryptography.fernet import Fernet

LOG_FILE = "logs.json"

# Initialize keys (should be stored securely in practice)
FERNET_KEY_FILE = "fernet.key"
MAC_KEY_FILE = "mac.key"

def load_or_create_keys():
    if not os.path.exists(FERNET_KEY_FILE):
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, "wb") as f:
            f.write(key)
    if not os.path.exists(MAC_KEY_FILE):
        with open(MAC_KEY_FILE, "wb") as f:
            f.write(os.urandom(32))

def get_keys():
    with open(FERNET_KEY_FILE, "rb") as f:
        enc_key = f.read()
    with open(MAC_KEY_FILE, "rb") as f:
        mac_key = f.read()
    return enc_key, mac_key

def rotate_keys():
    # Forward-integrity: rotate by hashing
    enc_key, mac_key = get_keys()
    new_enc_key = hashlib.sha256(enc_key).digest()[:32]
    new_mac_key = hashlib.sha256(mac_key).digest()
    with open(FERNET_KEY_FILE, "wb") as f:
        f.write(new_enc_key)
    with open(MAC_KEY_FILE, "wb") as f:
        f.write(new_mac_key)

def add_log_entry(log_message):
    enc_key, mac_key = get_keys()
    fernet = Fernet(enc_key)
    encrypted_log = fernet.encrypt(log_message.encode())
    mac = hashlib.sha256(mac_key + encrypted_log).hexdigest()

    log_entry = {
        "encrypted_log": encrypted_log.decode(),
        "mac": mac
    }

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    else:
        logs = []

    logs.append(log_entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

    rotate_keys()
