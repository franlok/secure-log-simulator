import streamlit as st
import json
import os
import shutil
import hashlib
import hmac
from cryptography.fernet import Fernet
from datetime import datetime

# ---- FILE & KEY SETUP ----
LOG_FILE = "logs.json"
FERNET_KEY_FILE = "fernet.key"
MAC_KEY_FILE = "mac.key"
ID_KEY_FILE = "id.key"
ARCHIVE_FOLDER = "logs_archive"

def load_or_create_keys():
    if not os.path.exists(FERNET_KEY_FILE):
        with open(FERNET_KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    if not os.path.exists(MAC_KEY_FILE):
        with open(MAC_KEY_FILE, "wb") as f:
            f.write(os.urandom(32))
    if not os.path.exists(ID_KEY_FILE):
        with open(ID_KEY_FILE, "wb") as f:
            f.write(os.urandom(32))

def get_keys():
    with open(FERNET_KEY_FILE, "rb") as f:
        enc_key = f.read()
    with open(MAC_KEY_FILE, "rb") as f:
        mac_key = f.read()
    with open(ID_KEY_FILE, "rb") as f:
        id_key = f.read()
    return enc_key, mac_key, id_key

def get_last_mac(logs):
    for entry in reversed(logs):
        if isinstance(entry, dict) and "mac" in entry:
            return entry["mac"]
    return ""

# ---- ADD LOG ENTRY ----
def add_log_entry(log_message):
    logs = load_logs()

    if logs and logs[-1].get("type") == "LogClose":
        st.error("❌ Batch is already sealed. Cannot add more logs.")
        return

    enc_key, mac_key, id_key = get_keys()
    fernet = Fernet(enc_key)
    encrypted_log = fernet.encrypt(log_message.encode())

    prev_mac = get_last_mac(logs)
    index = sum(1 for entry in logs if isinstance(entry, dict) and "encrypted_log" in entry)

    log_id = hmac.new(id_key, str(index).encode(), hashlib.sha256).hexdigest()
    mac_input = encrypted_log + prev_mac.encode()
    mac = hmac.new(mac_key, mac_input, hashlib.sha256).hexdigest()

    log_entry = {
        "id": log_id,
        "encrypted_log": encrypted_log.decode(),
        "mac": mac,
        "prev_mac": prev_mac
    }

    logs.append(log_entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

    st.success("✅ Log encrypted, MAC chained, and stored!")

# ---- CLOSE LOG BATCH ----
def close_log_batch():
    _, mac_key, _ = get_keys()
    logs = load_logs()
    if not logs:
        return "No logs to close."

    if logs[-1].get("type") == "LogClose":
        return "Batch is already sealed."

    last_mac = get_last_mac(logs)
    if not last_mac:
        return "No valid MAC found."

    batch_mac = hmac.new(mac_key, last_mac.encode(), hashlib.sha256).hexdigest()
    close_entry = {
        "type": "LogClose",
        "timestamp": datetime.now().isoformat(),
        "final_mac": batch_mac
    }

    logs.append(close_entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

    return "Log batch closed."

# ---- START NEW SESSION (ARCHIVE + RESET) ----
def start_new_session():
    if not os.path.exists(ARCHIVE_FOLDER):
        os.makedirs(ARCHIVE_FOLDER)
    if os.path.exists(LOG_FILE):
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        archive_name = f"{ARCHIVE_FOLDER}/logs_{timestamp}.json"
        shutil.move(LOG_FILE, archive_name)
    with open(LOG_FILE, "w") as f:
        json.dump([], f)

# ---- DECRYPT + VERIFY ----
def load_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    return []

def decrypt_log(encrypted_text, key):
    try:
        return Fernet(key).decrypt(encrypted_text.encode()).decode()
    except:
        return "[Decryption Failed]"

def verify_log_mac(entry, mac_key):
    if "type" in entry and entry["type"] == "LogClose":
        return True
    encrypted = entry["encrypted_log"].encode()
    prev = entry.get("prev_mac", "").encode()
    expected = hmac.new(mac_key, encrypted + prev, hashlib.sha256).hexdigest()
    return expected == entry["mac"]

# ---- STREAMLIT APP ----
st.set_page_config(page_title="Secure Log Demo", layout="centered")
load_or_create_keys()

# ---- SIDEBAR ----
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", [
    "📖 Help / Demo Guide",
    "Add Log", "View Logs", "View Archived Logs",
    "Close Log Batch",  "Start New Session",
    "Tamper Simulation", "Verifier Role", "Simulate Upload"
])



# ---- HEADER ----
st.title("🔐 Secure Log File Preparation Demo")
st.markdown("""
This tool demonstrates:
- 🔒 AES encryption with Fernet
- 🔁 MAC chaining for forward integrity
- 🧾 HMAC-based log ID
- 📦 Log-close records for batch sealing
- 🔄 Start new secure sessions while archiving old ones
""")

# ---- PAGE LOGIC ----
if page == "Add Log":
    st.header("📝 Add Log Entry")
    log_input = st.text_area("Log Message", "")
    if st.button("Encrypt & Save"):
        if log_input.strip() == "":
            st.error("Please enter a log message.")
        else:
            add_log_entry(log_input.strip())

elif page == "View Logs":
    st.header("📂 Stored Logs")
    logs = load_logs()
    if not logs:
        st.info("No logs yet.")
    else:
        has_key = st.checkbox("🔓 I have the decryption key", value=True)
        if has_key:
            enc_key, mac_key, _ = get_keys()

        for i, log in enumerate(logs):
            if log.get("type") == "LogClose":
                st.markdown(f"#### 🔚 Log Close Record")
                st.markdown(f"- 🕓 Timestamp: `{log['timestamp']}`")
                st.markdown(f"- ✅ Final MAC: `{log['final_mac'][:16]}...`")
            else:
                st.markdown(f"#### Log {i + 1}")
                st.markdown(f"- 🆔 ID: `{log['id'][:16]}...`")
                if has_key:
                    msg = decrypt_log(log["encrypted_log"], enc_key)
                    valid = verify_log_mac(log, mac_key)
                    st.markdown(f"- 🔐 Decrypted: `{msg}`")
                    st.markdown(f"- 🧾 MAC: `{log['mac'][:16]}...`")
                    st.markdown(f"- ✅ Integrity: {'✔️ Valid' if valid else '❌ Tampered'}")
                else:
                    st.markdown(f"- 🔒 Encrypted: `{log['encrypted_log'][:64]}...`")
                    st.markdown("- 🔐 MAC: [Hidden]")
            st.markdown("---")

elif page == "Close Log Batch":
    st.header("📦 Close Log Batch")
    if st.button("Seal Batch"):
        result = close_log_batch()
        st.success(result)


elif page == "Start New Session":
    st.header("🔄 Start New Session")
    st.warning("This will archive the current log file and start a new one.")
    if st.button("Archive and Reset"):
        start_new_session()
        st.success("✅ Archived old logs and started a new session!")
        
elif page == "View Archived Logs":
    st.header("📁 Archived Log Files")
    
    if not os.path.exists(ARCHIVE_FOLDER):
        st.info("No archived logs available.")
    else:
        archive_files = [f for f in os.listdir(ARCHIVE_FOLDER) if f.endswith(".json")]
        if not archive_files:
            st.info("No archived logs found.")
        else:
            selected_file = st.selectbox("Select an archived log file:", sorted(archive_files, reverse=True))
            if selected_file:
                with open(os.path.join(ARCHIVE_FOLDER, selected_file), "r") as f:
                    archived_logs = json.load(f)

                has_key = st.checkbox("🔓 I have the decryption key", value=True)
                if has_key:
                    enc_key, mac_key, _ = get_keys()

                for i, log in enumerate(archived_logs):
                    if log.get("type") == "LogClose":
                        st.markdown(f"#### 🔚 Log Close Record")
                        st.markdown(f"- 🕓 Timestamp: `{log['timestamp']}`")
                        st.markdown(f"- ✅ Final MAC: `{log['final_mac'][:16]}...`")
                    else:
                        st.markdown(f"#### Log {i + 1}")
                        st.markdown(f"- 🆔 ID: `{log['id'][:16]}...`")
                        if has_key:
                            msg = decrypt_log(log["encrypted_log"], enc_key)
                            valid = verify_log_mac(log, mac_key)
                            st.markdown(f"- 🔐 Decrypted: `{msg}`")
                            st.markdown(f"- 🧾 MAC: `{log['mac'][:16]}...`")
                            st.markdown(f"- ✅ Integrity: {'✔️ Valid' if valid else '❌ Tampered'}")
                        else:
                            st.markdown(f"- 🔒 Encrypted: `{log['encrypted_log'][:64]}...`")
                            st.markdown("- 🔐 MAC: [Hidden]")
                    st.markdown("---")
elif page == "Tamper Simulation":
    st.header("🐞 Simulate Log Tampering")

    logs = load_logs()
    tamper_candidates = [
        (i, log) for i, log in enumerate(logs)
        if isinstance(log, dict) and "encrypted_log" in log
    ]

    if not tamper_candidates:
        st.info("No logs available to tamper.")
    else:
        index_to_tamper = st.selectbox("Select log index to tamper:", [i for i, _ in tamper_candidates])
        if st.button("🧨 Tamper with selected log"):
            logs[index_to_tamper]["encrypted_log"] = "tampered" + logs[index_to_tamper]["encrypted_log"][8:]
            with open(LOG_FILE, "w") as f:
                json.dump(logs, f, indent=4)
            st.warning("🔧 Log tampered. Now try viewing logs to see integrity failure.")
elif page == "Verifier Role":
    st.header("🔐 Verifier Role: MAC-only Validation")

    logs = load_logs()
    if not logs:
        st.info("No logs found.")
    else:
        _, mac_key, _ = get_keys()
        for i, log in enumerate(logs):
            if log.get("type") == "LogClose":
                st.markdown(f"#### 🔚 Log Close Record")
                st.markdown(f"- 🕓 Timestamp: `{log['timestamp']}`")
                st.markdown(f"- ✅ Final MAC: `{log['final_mac'][:16]}...`")
            else:
                valid = verify_log_mac(log, mac_key)
                st.markdown(f"#### Log {i + 1}")
                st.markdown(f"- 🧾 MAC: `{log['mac'][:16]}...`")
                st.markdown(f"- ✅ Integrity (MAC Only): {'✔️ Valid' if valid else '❌ Tampered'}")
            st.markdown("---")
elif page == "Simulate Upload":
    st.header("📤 Simulate Upload to Untrusted Cloud")

    if st.button("🛰 Upload latest sealed archive to fake cloud"):
        archive_path = None
        if os.path.exists(ARCHIVE_FOLDER):
            archive_files = [
                f for f in os.listdir(ARCHIVE_FOLDER)
                if f.startswith("logs_") and f.endswith(".json")
            ]
            if archive_files:
                latest = sorted(archive_files, reverse=True)[0]
                archive_path = os.path.join(ARCHIVE_FOLDER, latest)

        if archive_path and os.path.exists(archive_path):
            if not os.path.exists("logs_cloud"):
                os.makedirs("logs_cloud")
            cloud_path = os.path.join("logs_cloud", f"cloud_copy_{latest}")
            shutil.copy(archive_path, cloud_path)
            st.success("✅ Simulated upload complete!")
            st.caption(f"Stored in: {cloud_path}")
        else:
            st.error("❌ No sealed log archive found to upload.")


if page == "📖 Help / Demo Guide":
    st.header("📖 How to Use This Secure Logging Demo")

    st.markdown("""
    Welcome! This tool is a simulation of a **Log-as-a-Service (LaaS)** system — where secure logs are created, sealed, and verified even on untrusted cloud platforms.

    ### 🔐 Key Security Features:
    - **AES Encryption (Fernet)**: Your log messages are fully encrypted for confidentiality.
    - **MAC Chaining**: Every log is cryptographically linked to the one before it — tampering breaks the chain.
    - **HMAC-based Log IDs**: Every log has a unique, verifiable ID to prevent forgery.

    ### 📦 Logging Workflow:
    - **Close Log Batch**: Once logs are written, you "seal" them. This prevents any further changes.
    - **Start New Session**: Begin a fresh batch after archiving the previous one for clean logging.

    ### 🧪 Interactive Features You Can Try:
    - **Tamper Simulation**: See what happens if someone tries to alter a log (spoiler: we catch them).
    - **Verifier Role**: Try being an auditor — check log integrity **without** seeing the actual content.
    - **Simulate Upload**: Emulates sending logs to the cloud. The logs stay secure and verifiable.
    - **Archived Logs Viewer**: Browse old sealed batches and verify they are still tamper-free.

    ---
    ### 🧠 Suggested Walkthrough (Try These Steps!)
    1. 🔐 Add a few secure log messages.
    2. 📦 Seal the batch — this locks the log set.
    3. 🚫 Try adding another log — it will be blocked.
    4. 🐞 Tamper with a log — and observe how the system detects it.
    5. 🔍 Use Verifier Role — check integrity without decrypting anything.
    6. 📁 Archive and start a new session — logs are saved safely.
    7. ☁️ Simulate a cloud upload — logs copied to a “cloud” folder.
    8. 🧾 View an older batch — and verify its integrity.

    """)

    st.success("✅ You can follow the steps above to explore how secure logs behave in a zero-trust environment!")


