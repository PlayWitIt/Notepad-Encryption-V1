import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Generate a key from the password using PBKDF2HMAC
def password_to_key(password):
    salt = b'\x00' * 16  # Ideally, use a unique salt per file
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Encrypt the selected file and overwrite the original file
def encrypt_file(file_path, key):
    try:
        fernet = Fernet(key)

        # Read the file content
        with open(file_path, "rb") as file:
            file_data = file.read()

        # Encrypt the file content
        encrypted_data = fernet.encrypt(file_data)

        # Rename the file to remember the original extension
        encrypted_file_path = file_path + ".encrypted"
        os.rename(file_path, encrypted_file_path)

        # Write the encrypted content back to the renamed file
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)

        messagebox.showinfo("Success", f"File encrypted successfully!\nFile saved as: {encrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error encrypting file: {str(e)}")

# Decrypt the selected file and overwrite the original file
def decrypt_file(file_path, key):
    try:
        fernet = Fernet(key)

        # Read the encrypted file content
        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        # Decrypt the content
        decrypted_data = fernet.decrypt(encrypted_data)

        # Remove the ".encrypted" extension to restore the original file name
        decrypted_file_path = file_path.replace(".encrypted", "")

        # Write the decrypted content to the original file
        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_data)

        # Optionally, you can delete the ".encrypted" file
        os.remove(file_path)

        messagebox.showinfo("Success", f"File decrypted successfully!\nFile restored as: {decrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error decrypting file: {str(e)}")

# File selection dialog
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file_path.delete(0, tk.END)
        entry_file_path.insert(0, file_path)

# Encrypt button callback
def on_encrypt():
    file_path = entry_file_path.get()
    password = entry_password.get()
    
    if not file_path or not password:
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return

    key = password_to_key(password)
    encrypt_file(file_path, key)

# Decrypt button callback
def on_decrypt():
    file_path = entry_file_path.get()
    password = entry_password.get()

    if not file_path or not password:
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return

    key = password_to_key(password)
    decrypt_file(file_path, key)

# Create the main window
root = tk.Tk()
root.title("File Encryption/Decryption")

# File path selection
lbl_file_path = tk.Label(root, text="Select File:")
lbl_file_path.grid(row=0, column=0, padx=10, pady=10)

entry_file_path = tk.Entry(root, width=50)
entry_file_path.grid(row=0, column=1, padx=10, pady=10)

btn_select_file = tk.Button(root, text="Browse", command=select_file)
btn_select_file.grid(row=0, column=2, padx=10, pady=10)

# Password input
lbl_password = tk.Label(root, text="Enter Password:")
lbl_password.grid(row=1, column=0, padx=10, pady=10)

entry_password = tk.Entry(root, width=50, show="*")
entry_password.grid(row=1, column=1, padx=10, pady=10)

# Encrypt and Decrypt buttons
btn_encrypt = tk.Button(root, text="Encrypt", command=on_encrypt, bg="green", fg="white")
btn_encrypt.grid(row=2, column=0, padx=10, pady=10)

btn_decrypt = tk.Button(root, text="Decrypt", command=on_decrypt, bg="blue", fg="white")
btn_decrypt.grid(row=2, column=1, padx=10, pady=10)

# Start the GUI event loop
root.mainloop()
