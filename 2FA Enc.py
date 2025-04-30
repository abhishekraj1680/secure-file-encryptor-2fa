import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pyotp
import qrcode
import secrets

# ======== Functions ========

def password_strength(password):
    import re
    if (len(password) >= 8 and
        re.search(r"[a-z]", password) and
        re.search(r"[A-Z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return True
    return False

def generate_key(password, salt=b'static_salt_here'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()

    key = generate_key(password)
    nonce = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()

    with open(filepath + ".enc", 'wb') as f:
        f.write(nonce + ct)

    os.remove(filepath)

def decrypt_file(filepath, password):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        nonce = data[:16]
        ct = data[16:]

        key = generate_key(password)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()

        out_path = filepath.replace(".enc", "")
        with open(out_path, 'wb') as f:
            f.write(pt)

        os.remove(filepath)

        print("Decryption successful!")
        return True

    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return False

def generate_totp_secret():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    qr = qrcode.make(totp.provisioning_uri("User", issuer_name="FileEncryptor"))
    qr.save("totp_qr.png")
    return secret

def verify_totp(secret, user_input_code):
    totp = pyotp.TOTP(secret)
    return totp.verify(user_input_code)

# ======== GUI Application ========

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Encryptor with 2FA")
        master.geometry("400x300")
        master.configure(bg="#e6f2ff")
        master.resizable(False, False)
        self.center_window(master)

        self.secret = generate_totp_secret()
        messagebox.showinfo("TOTP Setup", "TOTP QR Code saved as 'totp_qr.png'. Please scan with Google Authenticator.")

        self.title_label = tk.Label(master, text="Secure File Encryptor", font=("Helvetica", 18, "bold"), bg="#e6f2ff", fg="#003366")
        self.title_label.pack(pady=20)

        self.encrypt_button = tk.Button(master, text="🔒 Encrypt File", command=self.encrypt, width=20, height=2, bg="#3399ff", fg="white", font=("Helvetica", 12, "bold"), relief="raised", cursor="hand2")
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(master, text="🔓 Decrypt File", command=self.decrypt, width=20, height=2, bg="#00cc66", fg="white", font=("Helvetica", 12, "bold"), relief="raised", cursor="hand2")
        self.decrypt_button.pack(pady=10)

    def center_window(self, win):
        win.update_idletasks()
        width = win.winfo_width()
        height = win.winfo_height()
        x = (win.winfo_screenwidth() // 2) - (width // 2)
        y = (win.winfo_screenheight() // 2) - (height // 2)
        win.geometry('{}x{}+{}+{}'.format(400, 300, x, y))

    def encrypt(self):
        filepath = filedialog.askopenfilename(filetypes=[
            ("Python Files", "*.py"),
            ("All Files", "*.*")
        ])
        if filepath:
            password = simpledialog.askstring("Password", "Enter a strong password:", show='*')
            if password and password_strength(password):
                encrypt_file(filepath, password)
                messagebox.showinfo("Success", "File encrypted successfully!")
            else:
                messagebox.showerror("Error", "Weak password! Must be 8+ chars with upper, lower, digit, special char.")

    def decrypt(self):
        filepath = filedialog.askopenfilename(filetypes=[
            ("Encrypted Files", "*.enc"),
            ("All Files", "*.*")
        ])
        if filepath:
            totp_code = simpledialog.askstring("2FA", "Enter your TOTP code from Google Authenticator:")
            if verify_totp(self.secret, totp_code):
                password = simpledialog.askstring("Password", "Enter your password:", show='*')
                if decrypt_file(filepath, password):
                    messagebox.showinfo("Success", "File decrypted successfully!")
                else:
                    messagebox.showerror("Error", "Decryption failed! Please check the password and TOTP.")
            else:
                messagebox.showerror("Error", "Invalid TOTP code!")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
