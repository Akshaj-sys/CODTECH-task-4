import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def display_banner():
    print("=" * 65)
    print("CODTECH SECURE FILE ENCRYPTOR")
    print("=" * 65)

def generate_and_save_key(key_path="secret.key"):
    #32 bytes= 256 bits
    key = AESGCM.generate_key(bit_length=256)
    with open(key_path, "wb") as key_file:
        key_file.write(key)
    print(f"[SUCCESS] Fresh AES-256 key generated and saved to: {key_path}")
    print("[WARNING] Keep this key safe! Losing it means losing access to your encrypted files.")

def load_key(key_path="secret.key"):
    if not os.path.exists(key_path):
        print(f"[ERROR] Key file '{key_path}' not found. Please generate a key first.")
        return None
    with open (key_path, "rb") as key_file:
        return key_file.read()
    
def encrypt_file(file_path, key):
    if not os.path.exists(file_path):
        print(f"[ERROR] Target file '{file_path}' does not exist")
        return
    
    try:
        # Read the raw file contents
        with open(file_path, "rb") as f:
            data = f.read()

        # Initialize AES-256 GCM with our key
        aesgcm = AESGCM(key)
        
        # Generate a unique 12-byte Nonce (Number used Once) for initialization vector
        nonce = os.urandom(12)
        
        # Encrypt the data
        encrypted_data = aesgcm.encrypt(nonce, data, None)

        # Write the nonce + encrypted data back to a new secure file
        output_file = file_path + ".enc"
        with open(output_file, "wb") as f:
            f.write(nonce + encrypted_data)
            
        print(f"\n[SUCCESS] File encrypted successfully!")
        print(f" -> Protected Output: {output_file}")
    except Exception as e:
        print(f"[ERROR] Encryption operation failed: {e}")

def decrypt_file(encrypted_file_path, key):
    """Decrypts a file using AES-256 GCM."""
    if not os.path.exists(encrypted_file_path):
        print(f"[ERROR] Target file '{encrypted_file_path}' does not exist.")
        return

    try:
        with open(encrypted_file_path, "rb") as f:
            file_contents = f.read()

        # Extract the original 12-byte nonce from the front of the file
        nonce = file_contents[:12]
        actual_encrypted_data = file_contents[12:]

        # Initialize AES-256 GCM and decrypt
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, actual_encrypted_data, None)

        # Restore the original file (stripping the .enc extension)
        output_file = encrypted_file_path.replace(".enc", "")
        if output_file == encrypted_file_path:
            output_file = "decrypted_" + encrypted_file_path

        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        print(f"\n[SUCCESS] File decrypted and verified successfully!")
        print(f" -> Restored Output: {output_file}")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Decryption failed! The key is wrong or the file has been tampered with.")

def main_menu():
    while True:
        display_banner()
        print(" [1] Generate Fresh Encryption Key (AES-256)")
        print(" [2] Encrypt a File")
        print(" [3] Decryption / Verify a File")
        print(" [4] Exit Application")
        print("=" * 65)
        
        choice = input("\nSelect an operational mode (1-4): ").strip()
        
        if choice == '1':
            generate_and_save_key()
            input("\nPress Enter to return to menu...")
        
        elif choice in ['2', '3']:
            key = load_key()
            if key is None:
                input("\nPress Enter to return to menu...")
                continue
                
            file_target = input("\nEnter the exact path/name of the file: ").strip()
            if choice == '2':
                encrypt_file(file_target, key)
            else:
                decrypt_file(file_target, key)
            input("\nPress Enter to return to menu...")
            
        elif choice == '4':
            print("\n[+] Security vault locked down. Goodbye!")
            sys.exit(0)
        else:
            print("[ERROR] Invalid choice.")
            input("\nPress Enter to try again...")

if __name__ == "__main__":
    main_menu()