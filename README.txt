File Encryption/Decryption Tool
Description
This is a simple graphical user interface (GUI) tool for encrypting and decrypting files using symmetric encryption. The application uses the cryptography library to handle encryption and decryption, and tkinter for the GUI.

Features
Encrypt Files: Encrypt files with a password, generating an encrypted file with the .encrypted extension.
Decrypt Files: Decrypt files that have been encrypted, restoring the original file.
Key Components
password_to_key(password): Converts a password into an encryption key using PBKDF2HMAC.
encrypt_file(file_path, key): Encrypts a file and saves it with a .encrypted extension.
decrypt_file(file_path, key): Decrypts an encrypted file and restores the original file.
Installation
To use this tool, you need to install the required dependencies. You can install them using pip:

bash
Copy code
pip install cryptography
Usage
Run the Application: Execute the script to open the GUI.

Select File: Click the "Browse" button to select the file you want to encrypt or decrypt.

Enter Password: Provide a password to be used for encryption or decryption.

Encrypt/Decrypt: Click the "Encrypt" button to encrypt the selected file or the "Decrypt" button to decrypt an encrypted file.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Contributing
Contributions are welcome! Please focus on educational purposes and improvements related to the study material. Pull requests will not be accepted until after the release of the educational video.