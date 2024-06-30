import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_file(file_path: str, password: str):
    try:
        salt = os.urandom(16)
        key = generate_key(password, salt)
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        original_extension = os.path.splitext(file_path)[1]
        output_path = os.path.splitext(file_path)[0] + '.enc'
        with open(output_path, 'wb') as f:
            for _ in tqdm(range(100), desc="Encrypting", unit="block"):
                pass
            f.write(salt + iv + len(original_extension).to_bytes(1, 'big') + original_extension.encode() + ciphertext)
        clear_screen()
        print(f"{Fore.GREEN}File encrypted successfully: {output_path}")
        print("Type 3 to exit.")
    except PermissionError as e:
        print(f"{Fore.RED}Permission Error: {e}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

def decrypt_file(file_path: str, password: str):
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            extension_length = int.from_bytes(f.read(1), 'big')
            original_extension = f.read(extension_length).decode()
            ciphertext = f.read()
        
        key = generate_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        output_path = os.path.splitext(file_path)[0] + original_extension
        with open(output_path, 'wb') as f:
            for _ in tqdm(range(100), desc="Decrypting", unit="block"):
                pass
            f.write(plaintext)
        clear_screen()
        print(f"{Fore.GREEN}File decrypted successfully: {output_path}")
        print("Type 3 to exit.")
    except PermissionError as e:
        print(f"{Fore.RED}Permission Error: {e}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

def main_menu():
    ascii_title = f"""
{Fore.WHITE}
███████╗██╗██╗     ███████╗     ███████╗██╗███████╗██╗   ██╗
██╔════╝██║██║     ██╔════╝     ██╔════╝██║██╔════╝██║   ██║
█████╗  ██║██║     █████╗       █████╗  ██║█████╗  ██║   ██║
██╔══╝  ██║██║     ██╔══╝       ██╔══╝  ██║██╔══╝  ██║   ██║
██║     ██║███████╗███████╗     ██║     ██║██║     ╚██████╔╝
╚═╝     ╚═╝╚══════╝╚══════╝     ╚═╝     ╚═╝╚═╝      ╚═════╝ 
{Style.RESET_ALL}
"""
    while True:
        clear_screen()
        print(ascii_title)
        print("Welcome to File FIFU")
        print(f"{Fore.CYAN}1. Encrypt File")
        print(f"{Fore.CYAN}2. Decrypt File")
        print(f"{Fore.CYAN}3. Exit")

        choice = input("Enter your choice: ")
        if choice == '1':
            file_path = input("Enter the path of the file to encrypt: ")
            password = input("Enter the encryption password: ")
            encrypt_file(file_path, password)
        elif choice == '2':
            file_path = input("Enter the path of the file to decrypt: ")
            password = input("Enter the decryption password: ")
            decrypt_file(file_path, password)
        elif choice == '3':
            clear_screen()
            print("Goodbye!")
            sys.exit()
        else:
            clear_screen()
            print(f"{Fore.RED}Invalid choice, please try again.")

if __name__ == "__main__":
    main_menu()
