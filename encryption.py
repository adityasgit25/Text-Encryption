import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from hashlib import sha256
import base64

# Padding utilities
def pad(text, block_size):
    return text + (block_size - len(text) % block_size) * ' '

def unpad(text):
    return text.rstrip()

# AES encryption and decryption
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_text.encode())
    return base64.b64encode(ciphertext).decode()

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decoded_data = base64.b64decode(ciphertext)
    decrypted_text = cipher.decrypt(decoded_data).decode()
    return unpad(decrypted_text)

# DES encryption and decryption
def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext, DES.block_size)
    ciphertext = cipher.encrypt(padded_text.encode())
    return base64.b64encode(ciphertext).decode()

def des_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decoded_data = base64.b64decode(ciphertext)
    decrypted_text = cipher.decrypt(decoded_data).decode()
    return unpad(decrypted_text)

# RSA encryption and decryption
def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decoded_data = base64.b64decode(ciphertext)
    decrypted_text = cipher.decrypt(decoded_data).decode()
    return decrypted_text

# Hashing with SHA-256
def hash_sha256(text):
    return sha256(text.encode()).hexdigest()

# GUI for the encryption tool
def build_gui():
    window = tk.Tk()
    window.title("Text Encryption Tool")
    window.geometry('500x500')

    # Text input field
    lbl_text = tk.Label(window, text="Enter Text:")
    lbl_text.pack()
    text_input = scrolledtext.ScrolledText(window, width=50, height=5)
    text_input.pack()

    # Output field
    lbl_output = tk.Label(window, text="Output:")
    lbl_output.pack()
    output_field = scrolledtext.ScrolledText(window, width=50, height=5)
    output_field.pack()

    # AES encryption/decryption
    def aes_action():
        key = get_random_bytes(16)
        plaintext = text_input.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showerror("Input Error", "Please enter text to encrypt!")
            return
        ciphertext = aes_encrypt(plaintext, key)
        decrypted_text = aes_decrypt(ciphertext, key)
        output_field.delete("1.0", tk.END)
        output_field.insert(tk.END, f"Encrypted (AES): {ciphertext}\nDecrypted (AES): {decrypted_text}")

    # DES encryption/decryption
    def des_action():
        key = get_random_bytes(8)
        plaintext = text_input.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showerror("Input Error", "Please enter text to encrypt!")
            return
        ciphertext = des_encrypt(plaintext, key)
        decrypted_text = des_decrypt(ciphertext, key)
        output_field.delete("1.0", tk.END)
        output_field.insert(tk.END, f"Encrypted (DES): {ciphertext}\nDecrypted (DES): {decrypted_text}")

    # RSA encryption/decryption
    def rsa_action():
        private_key, public_key = rsa_generate_keys()
        plaintext = text_input.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showerror("Input Error", "Please enter text to encrypt!")
            return
        ciphertext = rsa_encrypt(plaintext, public_key)
        decrypted_text = rsa_decrypt(ciphertext, private_key)
        output_field.delete("1.0", tk.END)
        output_field.insert(tk.END, f"Encrypted (RSA): {ciphertext}\nDecrypted (RSA): {decrypted_text}")

    # SHA-256 Hashing
    def hash_action():
        plaintext = text_input.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showerror("Input Error", "Please enter text to hash!")
            return
        hashed_text = hash_sha256(plaintext)
        output_field.delete("1.0", tk.END)
        output_field.insert(tk.END, f"SHA-256 Hash: {hashed_text}")

    # Buttons for different encryption actions
    btn_aes = tk.Button(window, text="AES Encrypt/Decrypt", command=aes_action)
    btn_aes.pack(pady=5)

    btn_des = tk.Button(window, text="DES Encrypt/Decrypt", command=des_action)
    btn_des.pack(pady=5)

    btn_rsa = tk.Button(window, text="RSA Encrypt/Decrypt", command=rsa_action)
    btn_rsa.pack(pady=5)

    btn_hash = tk.Button(window, text="SHA-256 Hash", command=hash_action)
    btn_hash.pack(pady=5)

    # Start the GUI loop
    window.mainloop()

# Run the GUI
if __name__ == "__main__":
    build_gui()
