import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os

# --- 🔐 Key Management ---

KEY_FILE = "secret.key"

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
        return key

KEY = load_or_create_key()
cipher = Fernet(KEY)


if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {} 

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'authorized' not in st.session_state:
    st.session_state.authorized = True


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, input_passkey):
    hashed_input = hash_passkey(input_passkey)

    for record in st.session_state.stored_data.values():
        if record["encrypted_text"] == encrypted_text:
            if record["hashed_passkey"] == hashed_input:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
            else:
                st.session_state.failed_attempts += 1
                return None

    st.session_state.failed_attempts += 1
    return None



def home_page():
    st.title("🏠 Home - Secure Data System")
    st.write("Welcome! Use the sidebar to Store or Retrieve your encrypted data.")

def store_data_page():
    st.title("📂 Store New Data")
    text = st.text_area("Enter text to encrypt:")
    passkey = st.text_input("Enter a secret passkey:", type="password")
    
    if st.button("Encrypt & Save"):
        if text and passkey:
            encrypted = encrypt_data(text)
            hashed_pass = hash_passkey(passkey)
            st.session_state.stored_data[encrypted] = {"encrypted_text": encrypted, "hashed_passkey": hashed_pass}
            st.success("✅ Data encrypted and saved successfully!")
            st.text(f"Encrypted Text (save this!):\n{encrypted}")
        else:
            st.error("⚠️ Both fields are required!")

def retrieve_data_page():
    st.title("🔍 Retrieve Stored Data")
    
    if not st.session_state.authorized:
        st.warning("🔒 You must login first!")
        return

    encrypted_text = st.text_area("Enter Encrypted Text:")
    passkey = st.text_input("Enter your passkey:", type="password")
    
    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success(f"✅ Decrypted Text: {result}")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                if attempts_left > 0:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.error("🚨 Too many failed attempts! Please login again.")
                    st.session_state.authorized = False
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

def login_page():
    st.title("🔑 Reauthorization Required")
    master_password = st.text_input("Enter Master Password:", type="password")
    
    if st.button("Login"):
        if master_password == "admin123":
            st.success("✅ Login successful!")
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.rerun()
        else:
            st.error("❌ Incorrect master password!")



st.sidebar.title("🔐 Menu")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Select Page", menu)

if choice == "Home":
    home_page()
elif choice == "Store Data":
    store_data_page()
elif choice == "Retrieve Data":
    retrieve_data_page()
elif choice == "Login":
    login_page()
