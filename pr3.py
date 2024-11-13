import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# AES функції
def derive_aes_key_and_iv(passphrase: bytes, salt_value: bytes):
    kdf = Scrypt(salt=salt_value, length=32, n=2**14, r=8, p=1, backend=default_backend())
    derived_key = kdf.derive(passphrase)
    init_vector = os.urandom(16)
    return derived_key, init_vector

def encrypt_with_aes(source_file: str, destination_file: str, passphrase: bytes):
    salt_value = os.urandom(16)
    key, iv = derive_aes_key_and_iv(passphrase, salt_value)

    with open(source_file, 'rb') as f:
        data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b"\0" * (16 - len(data) % 16)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    mac = HMAC(key, hashes.SHA256(), backend=default_backend())
    mac.update(encrypted_data)
    hmac_tag = mac.finalize()

    with open(destination_file, 'wb') as f:
        f.write(salt_value + iv + hmac_tag + encrypted_data)

def decrypt_with_aes(source_file: str, destination_file: str, passphrase: bytes):
    with open(source_file, 'rb') as f:
        salt_value, iv, hmac_tag = f.read(16), f.read(16), f.read(32)
        encrypted_data = f.read()

    key, _ = derive_aes_key_and_iv(passphrase, salt_value)

    mac = HMAC(key, hashes.SHA256(), backend=default_backend())
    mac.update(encrypted_data)
    mac.verify(hmac_tag)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    original_data = decrypted_data.rstrip(b"\0")

    with open(destination_file, 'wb') as f:
        f.write(original_data)

# RSA функції
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt_message(message: bytes, rsa_public_key):
    return rsa_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_message(encrypted_message: bytes, rsa_private_key):
    return rsa_private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_encrypt_file(source_file: str, destination_file: str, public_key_path: str):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    with open(source_file, "rb") as f:
        data = f.read()

    encrypted_data = rsa_encrypt_message(data, public_key)

    with open(destination_file, "wb") as f:
        f.write(encrypted_data)

def rsa_decrypt_file(source_file: str, destination_file: str, private_key_path: str):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    with open(source_file, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = rsa_decrypt_message(encrypted_data, private_key)

    with open(destination_file, "wb") as f:
        f.write(decrypted_data)

def create_digital_signature(file_path: str, private_key_path: str, signature_file_path: str):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(signature_file_path, "wb") as f:
        f.write(signature)

def verify_digital_signature(file_path: str, public_key_path: str, signature_file_path: str):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    with open(file_path, "rb") as f:
        data = f.read()

    with open(signature_file_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Генерація паролю
def generate_password(length):
    chars = r'!\"#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
    return "".join(chars[os.urandom(1)[0] % len(chars)] for _ in range(length))

# Інтерфейс
class SecureApp:
    def __init__(self, window):
        self.window = window
        self.window.title("Прилажуха")

        self.encrypt_btn = tk.Button(window, text="Зашифрувати файл aes", command=self.aes_encrypt_handler)
        self.encrypt_btn.pack()

        self.decrypt_btn = tk.Button(window, text="Дешифрувати файл aes", command=self.aes_decrypt_handler)
        self.decrypt_btn.pack()

        self.keygen_btn = tk.Button(window, text="Генерування RSA Ключ", command=self.rsa_keygen_handler)
        self.keygen_btn.pack()

        self.rsa_encrypt_btn = tk.Button(window, text="Зашифрувати файл RSA", command=self.rsa_encrypt_handler)
        self.rsa_encrypt_btn.pack()

        self.rsa_decrypt_btn = tk.Button(window, text="Дешифрувати файл RSA", command=self.rsa_decrypt_handler)
        self.rsa_decrypt_btn.pack()

        self.sign_btn = tk.Button(window, text="Підпис файлу", command=self.sign_file_handler)
        self.sign_btn.pack()

        self.verify_btn = tk.Button(window, text="Перевірка підпису", command=self.verify_signature_handler)
        self.verify_btn.pack()

        self.pass_label = tk.Label(window, text="Введи пароль курва я пердоле:")
        self.pass_label.pack()
        self.pass_entry = tk.Entry(window, show="*")
        self.pass_entry.pack()

    # Обробники
    def aes_encrypt_handler(self):
        source_file = filedialog.askopenfilename(title="Choose File to Encrypt")
        destination_file = filedialog.asksaveasfilename(title="Save Encrypted File As")
        generated_pass = generate_password(10)
        with open('password_file.txt', "w") as f:
            f.write(generated_pass)
        encrypt_with_aes(source_file, destination_file, bytes(generated_pass, 'UTF-8'))
        messagebox.showinfo("Success", "File successfully encrypted!")

    def aes_decrypt_handler(self):
        source_file = filedialog.askopenfilename(title="Choose File to Decrypt")
        destination_file = filedialog.asksaveasfilename(title="Save Decrypted File As")
        passphrase = self.pass_entry.get().encode()
        decrypt_with_aes(source_file, destination_file, passphrase)
        messagebox.showinfo("Success", "File successfully decrypted!")

    def rsa_keygen_handler(self):
        priv_key, pub_key = generate_rsa_key_pair()
        file_path = filedialog.asksaveasfilename(title="Save Key Pair Base Name")
        base_name = os.path.splitext(file_path)[0]
        with open(base_name + "_private.pem", "wb") as f:
            f.write(priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(base_name + "_public.pem", "wb") as f:
            f.write(pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        messagebox.showinfo("Keys Saved", "RSA Key Pair Generated and Saved!")

    def rsa_encrypt_handler(self):
        source_file = filedialog.askopenfilename(title="Choose File to Encrypt")
        destination_file = filedialog.asksaveasfilename(title="Save Encrypted File As")
        public_key_path = filedialog.askopenfilename(title="Choose Public Key")
        rsa_encrypt_file(source_file, destination_file, public_key_path)
        messagebox.showinfo("Success", "File successfully encrypted with RSA!")

    def rsa_decrypt_handler(self):
        source_file = filedialog.askopenfilename(title="Choose File to Decrypt")
        destination_file = filedialog.asksaveasfilename(title="Save Decrypted File As")
        private_key_path = filedialog.askopenfilename(title="Choose Private Key")
        rsa_decrypt_file(source_file, destination_file, private_key_path)
        messagebox.showinfo("Success", "File successfully decrypted with RSA!")

    def sign_file_handler(self):
        file_path = filedialog.askopenfilename(title="Choose File to Sign")
        private_key_path = filedialog.askopenfilename(title="Choose Private Key")
        signature_file_path = filedialog.asksaveasfilename(title="Save Signature As")
        create_digital_signature(file_path, private_key_path, signature_file_path)
        messagebox.showinfo("Success", "File successfully signed!")

    def verify_signature_handler(self):
        file_path = filedialog.askopenfilename(title="Choose File to Verify")
        public_key_path = filedialog.askopenfilename(title="Choose Public Key")
        signature_file_path = filedialog.askopenfilename(title="Choose Signature File")
        if verify_digital_signature(file_path, public_key_path, signature_file_path):
            messagebox.showinfo("Success", "Signature is valid!")
        else:
            messagebox.showerror("Error", "Invalid signature!")

root = tk.Tk()
app = SecureApp(root)
root.mainloop()
