import tkinter as tk
from tkinter import messagebox, filedialog
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
import os
import json
import base64

def load_data():
    try:
        with open("../DSA Project/contract_data.json", "r") as file:
            data = json.load(file)
            return data.get("contracts", {})
    except FileNotFoundError:
        return {}

def save_data():
    with open("../DSA Project/contract_data.json", "w") as file:
        data = {"contracts": contracts}
        json.dump(data, file, indent=4)

key_management_system = {}

def save_private_key(private_key, file_path, password):
    key_management_system[file_path] = {
        "private_key": private_key,
        "password": password,
    }

def load_private_key(file_path, password):
    if file_path not in key_management_system:
        raise ValueError("Key not found")

    stored_data = key_management_system[file_path]
    if stored_data["password"] != password:
        raise ValueError("Invalid password")

    return stored_data["private_key"]

def generate_private_key():
    return ECC.generate(curve='P-256')

def save_private_key(private_key, file_path, password):
    private_key_bytes = private_key.export_key(format="PEM")
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key_bytes)
    encrypted_data = salt + ciphertext + tag
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

def load_private_key(file_path, password):
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    salt = encrypted_data[:16]
    ciphertext = encrypted_data[16:-16]
    tag = encrypted_data[-16:]
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_EAX, nonce=salt)
    private_key_bytes = cipher.decrypt(ciphertext)
    cipher.verify(tag)
    private_key = ECC.import_key(private_key_bytes)
    return private_key

def create_contract():
    name = contract_name_entry.get()
    data = contract_data_entry.get()
    contract = DigitalContract(name, data)
    salt = os.urandom(16)
    password = password_entry.get()
    symmetric_key = decrypt_symmetric_key_with_password(password, salt)
    if symmetric_key:
        encrypted_data, iv = encrypt_data(data, symmetric_key)
        signature = create_digital_signature(private_key, encrypted_data)
        contracts[name] = {
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "iv": base64.b64encode(iv).decode(),
            "salt": base64.b64encode(salt).decode(),
            "signature": base64.b64encode(signature).decode()
        }
        messagebox.showinfo("Success", "Contract created and encrypted with your password.")
    else:
        messagebox.showerror("Error", "Failed to derive the symmetric key from the password.")

def display_contract_details(contract_name, contract_data):
    contract_window = tk.Toplevel(root)
    contract_window.title("Contract Details")
    contract_name_label = tk.Label(contract_window, text="Contract Name:")
    contract_name_label.grid(row=0, column=0)
    contract_name_text = tk.Label(contract_window, text=contract_name)
    contract_name_text.grid(row=0, column=1)
    contract_data_label = tk.Label(contract_window, text="Contract Data:")
    contract_data_label.grid(row=1, column=0)
    contract_data_text = tk.Label(contract_window, text=contract_data)
    contract_data_text.grid(row=1, column=1)
    encryption_key_label = tk.Label(contract_window, text="Encryption Key:")
    encryption_key_label.grid(row=2, column=0)
    if contract_name in contracts:
        contract_data = contracts[contract_name]
        encryption_key = contract_data.get("symmetric_key", "Not available")
    else:
        encryption_key = "Not available"
    encryption_key_text = tk.Label(contract_window, text="**********")
    encryption_key_text.grid(row=2, column=1)
    password_label = tk.Label(contract_window, text="Password:")
    password_label.grid(row=3, column=0)
    password_entry = tk.Entry(contract_window, show="*")
    password_entry.grid(row=3, column=1)
    unlock_button = tk.Button(contract_window, text="View Encryption Key", command=lambda: view_encryption_key(password_entry, encryption_key_text, encryption_key))
    unlock_button.grid(row=4, column=1)
    view_uploaded_contract_button.grid(row=7, column=0, columnspan=2)

def view_encryption_key(password_entry, encryption_key_text, encryption_key):
    entered_password = password_entry.get()
    correct_password = entered_password
    if entered_password == correct_password:
        encryption_key_text.config(text=encryption_key)
    else:
        encryption_key_text.config(text="Incorrect password")

def verify_contract():
    contract_name = verify_contract_name_entry.get()
    if contract_name in contracts:
        contract_data = contracts[contract_name]
        encrypted_data = base64.b64decode(contract_data["encrypted_data"])
        iv = base64.b64decode(contract_data["iv"])
        signature = base64.b64decode(contract_data["signature"])
        salt = base64.b64decode(contract_data["salt"])
        password = verify_password_entry.get()
        symmetric_key = decrypt_symmetric_key_with_password(password, salt)
        if symmetric_key:
            try:
                decrypted_data = decrypt_data(encrypted_data, symmetric_key, iv)
                verify_result = verify_digital_signature(private_key, encrypted_data, signature)
                if verify_result:
                    messagebox.showinfo("Success", "Contract is valid and authentic.")
                    if contract_name in contracts:
                        contract_data["symmetric_key"] = base64.b64encode(symmetric_key).decode()
                    save_data()
                    display_contract_details(contract_name, decrypted_data)
                else:
                    messagebox.showerror("Error", "Contract is not valid or has been tampered with.")
            except ValueError:
                messagebox.showerror("Error", "Password is incorrect or the key is corrupted.")
        else:
            messagebox.showerror("Error", "Password is incorrect or the key is corrupted.")
    else:
        messagebox.showerror("Error", "Contract not found.")

def decrypt_symmetric_key_with_password(password, salt):
    derived_key = PBKDF2(password.encode(), salt, dkLen=16, count=100000)
    return derived_key

class DigitalContract:
    def __init__(self, name, data):
        self.name = name
        self.data = data

    def get_name(self):
        return self.name

    def get_data(self):
        return self.data

    def set_symmetric_key(self, key):
        self.symmetric_key = key

def generate_symmetric_key():
    return os.urandom(16)

def create_digital_signature(private_key, data):
    h = SHA256.new(data)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
    return signature

def verify_digital_signature(public_key, data, signature):
    h = SHA256.new(data)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

def encrypt_data(data, symmetric_key):
    iv = os.urandom(16)
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode(), 16))
    return encrypted_data, iv

def decrypt_data(encrypted_data, symmetric_key, iv):
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), 16)
    return decrypted_data.decode()

def upload_contract():
    file_path = filedialog.askopenfilename()
    with open(file_path, "r") as f:
        contract_data = f.read()
    with open("../DSA Project/uploaded_contract_data.txt", "w") as f:
        f.write(contract_data)
    messagebox.showinfo("Success", "Contract data uploaded and saved.")

def view_uploaded_contract():
    try:
        with open("../DSA Project/uploaded_contract_data.txt", "r") as f:
            uploaded_contract_data = f.read()
        uploaded_contract_window = tk.Toplevel(root)
        uploaded_contract_window.title("Uploaded Contract Data")
        uploaded_contract_label = tk.Label(uploaded_contract_window, text=uploaded_contract_data)
        uploaded_contract_label.pack()
    except FileNotFoundError:
        messagebox.showerror("Error", "Uploaded contract data not found. Please upload a contract first.")

def exit_app():
    root.destroy()

root = tk.Tk()
root.title("Contract Management System")
contract_name_label = tk.Label(root, text="Contract Name:")
contract_name_entry = tk.Entry(root)
contract_data_label = tk.Label(root, text="Contract Data:")
contract_data_entry = tk.Entry(root)
password_label = tk.Label(root, text="Your Password:")
password_entry = tk.Entry(root, show="*")
create_button = tk.Button(root, text="Create Contract", command=create_contract)
verify_contract_name_label = tk.Label(root, text="Contract Name:")
verify_contract_name_entry = tk.Entry(root)
verify_password_label = tk.Label(root, text="Your Password:")
verify_password_entry = tk.Entry(root, show="*")
verify_button = tk.Button(root, text="Verify Contract", command=verify_contract)
view_uploaded_contract_button = tk.Button(root, text="View Uploaded Contract", command=view_uploaded_contract)
save_button = tk.Button(root, text="Save Data", command=save_data)
exit_button = tk.Button(root, text="Exit", command=exit_app)
upload_button = tk.Button(root, text="Upload Contract", command=upload_contract)
contract_name_label.grid(row=0, column=0)
contract_name_entry.grid(row=0, column=1)
contract_data_label.grid(row=1, column=0)
contract_data_entry.grid(row=1, column=1)
upload_button.grid(row=2, column=0, columnspan=2)
password_label.grid(row=3, column=0)
password_entry.grid(row=3, column=1)
create_button.grid(row=4, column=0, columnspan=2)
verify_contract_name_label.grid(row=5, column=0)
verify_contract_name_entry.grid(row=5, column=1)
verify_password_label.grid(row=6, column=0)
verify_password_entry.grid(row=6, column=1)
verify_button.grid(row=7, column=0, columnspan=2)
save_button.grid(row=8, column=0, columnspan=2)
exit_button.grid(row=9, column=0, columnspan=2)
contracts = {}
private_key = generate_private_key()
root.mainloop()
