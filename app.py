import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet



# ========== Custom Styling ==========

st.markdown("""
    <style>
    /* Body Gradient */
    body {
        background: linear-gradient(135deg, #6c5ce7, #74b9ff);
        background-attachment: fixed;
    }

    .stApp {
        background: transparent;
        font-family: 'Segoe UI', sans-serif;
        color: #ffffff;
    }

    h1, h2, h3, h4 {
        color: #ffffff;
    }

    /* Content Box Styling */
    .css-1cpxqw2, .css-1d391kg {
        background-color: rgba(255, 255, 255, 0.9);
        padding: 20px;
        border-radius: 12px;
        box-shadow: 2px 4px 20px rgba(0,0,0,0.1);
        color: #2c2c54;
    }

    /* Button Styling */
    .stButton > button {
        background-color: #6c5ce7;
        color: white;
        font-weight: bold;
        border: none;
        border-radius: 8px;
        padding: 10px 20px;
        margin-top: 10px;
        transition: background-color 0.3s ease;
    }

    .stButton > button:hover {
        background-color: #4b39d1;
    }

    /* Inputs Styling */
    .stTextInput > div > input,
    .stTextArea textarea {
        border-radius: 6px;
        padding: 10px;
        border: 1px solid #ccc;
        background-color: #ffffff;
    }

    .stTextInput > div > input:focus,
    .stTextArea textarea:focus {
        border: 1px solid #6c5ce7;
        outline: none;
        box-shadow: 0 0 5px rgba(108, 92, 231, 0.4);
    }

    /* Sidebar Beautiful Gradient Background with Container */
    [data-testid="stSidebar"] {
        background: linear-gradient(135deg, #6c5ce7, #74b9ff);
        padding: 20px 15px;
    }

    /* Inner sidebar container */
    [data-testid="stSidebar"] > div:first-child {
        background-color: rgba(255, 255, 255, 0.1);
        padding: 20px;
        border-radius: 15px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    }

    /* Sidebar text and elements */
    [data-testid="stSidebar"] * {
        color: white;
        font-weight: 500;
    }
            
    /* Style for the logged-in user info */
.sidebar-user-info {
    background-color: rgba(255, 255, 255, 0.15);
    padding: 10px 15px;
    margin-bottom: 15px;
    border-radius: 10px;
    font-weight: bold;
    color: #ffffff;
    font-size: 15px;
}


    </style>
""", unsafe_allow_html=True)


# ========== Config ==========
USER_FILE = "users.json"
DATA_FILE = "secure_data.json"

# Generate/load encryption key
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as f:
        f.write(Fernet.generate_key())

with open("secret.key", "rb") as f:
    KEY = f.read()

cipher = Fernet(KEY)

# ========== Utility Functions ==========

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def load_json(file):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return {}

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# ========== Load Data ==========
users = load_json(USER_FILE)
data_store = load_json(DATA_FILE)

# ========== Session State ==========
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

# ========== Pages ==========

def register_page():
    st.title("📝 Register New Account")
    new_user = st.text_input("Choose a Username")
    new_pass = st.text_input("Choose a Password", type="password")

    if st.button("Register"):
        if new_user and new_pass:
            if new_user in users:
                st.warning("⚠️ Username already exists!")
            else:
                users[new_user] = hash_passkey(new_pass)
                save_json(USER_FILE, users)
                st.success("✅ Registered! You can now log in.")
        else:
            st.error("❗ Both fields are required.")

def login_page():
    st.title("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in users and users[username] == hash_passkey(password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.failed_attempts = 0
            st.success("✅ Login successful!")
            st.rerun()  # Refresh UI
        else:
            st.error("❌ Invalid username or password")

def logout():
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.failed_attempts = 0
    st.success("👋 Logged out.")
    st.rerun()

def home_page():
    st.title("🏠 Welcome To Secure Data Encryption System")
    st.write("Use this secure system to **encrypt and retrieve your data** with a unique passkey.")

def store_data_page():
    st.header("📥 Store Data")
    user_data = st.text_area("Enter Data")
    passkey = st.text_input("Enter a Passkey", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)

            data_store[st.session_state.username] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_json(DATA_FILE, data_store)
            st.success("✅ Data stored securely!")
        else:
            st.error("❗ Fill all fields.")

def retrieve_data_page():
    st.header("📤 Retrieve Your Data")
    passkey = st.text_input("Enter Your Passkey", type="password")

    if st.button("Decrypt"):
        user_record = data_store.get(st.session_state.username)

        if user_record:
            if hash_passkey(passkey) == user_record["passkey"]:
                decrypted = decrypt_data(user_record["encrypted_text"])
                st.success(f"✅ Decrypted Data: {decrypted}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey! Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts. Please log in again.")
                    st.session_state.logged_in = False
                    st.rerun()
        else:
            st.warning("ℹ️ No data found for your account.")

# ========== Sidebar Navigation ==========
if st.session_state.logged_in:
    sidebar_menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
    st.sidebar.markdown(f"<div class='sidebar-user-info'>👤 Logged in as: `{st.session_state.username}`</div>", unsafe_allow_html=True)

else:
    sidebar_menu = ["Login", "Register"]

menu = st.sidebar.radio("Menu", sidebar_menu)

# ========== Routing ==========
if menu == "Login":
    login_page()
elif menu == "Register":
    register_page()
elif menu == "Home":
    home_page()
elif menu == "Store Data":
    store_data_page()
elif menu == "Retrieve Data":
    retrieve_data_page()
elif menu == "Logout":
    logout()

