import subprocess
import os
import secrets
import string


# Read the English text file of alice
with open("alice_en_msg.txt", "r", encoding="utf-8") as f:
    english_text = f.read()

# Read the German text file
with open("alice_de_msg.txt", "r", encoding="utf-8") as f:
    german_text = f.read()


def generate_random_password(length=20):
    # Generate a strong random password
    # Use letters, digits, and special characters
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    # Use secrets module for cryptographically secure random generation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password


def alice_create_message(message, filename):
    # Alice creates a message file to send to Bob
    print(f"\n[ALICE] Creating message file...")
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(message)
    print(f"[ALICE] Message saved to: {filename}")
    print(f"[ALICE] Message length: {len(message)} characters")
    return filename


def alice_encrypt_message(input_file, output_file, password):
    # Alice encrypts the message using OpenSSL AES-128-CBC
    print(f"\n[ALICE] Encrypting message for Bob...")
    print(f"[ALICE] Using: AES-128-CBC with PBKDF2 and Salt")
    print(f"[ALICE] Password: {'*' * len(password)} (hidden for security)")
    
    try:
        # OpenSSL encryption command
        cmd = [
            'openssl', 'enc', '-aes-128-cbc',
            '-salt',           # Add salt for security
            '-pbkdf2',         # Use PBKDF2 for key derivation
            '-in', input_file,
            '-out', output_file,
            '-pass', f'pass:{password}'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            file_size = os.path.getsize(output_file)
            print(f"[ALICE] Encryption successful!")
            print(f"[ALICE] Encrypted file: {output_file}")
            print(f"[ALICE] File size: {file_size} bytes")
            
            # Show hex preview
            with open(output_file, 'rb') as f:
                first_bytes = f.read(32)
                hex_preview = ' '.join(f'{b:02x}' for b in first_bytes)
                print(f"[ALICE] Hex preview: {hex_preview}...")
            
            return True
        else:
            print(f"[ALICE] Encryption failed!")
            print(f"[ALICE] Error: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[ALICE] Error during encryption: {e}")
        return False


def alice_send_to_bob(encrypted_file, password):
    # Alice sends the encrypted file to Bob
    print(f"\n[ALICE] Sending encrypted message to Bob...")
    print(f"[ALICE] Encrypted file: {encrypted_file}")
    print(f"[ALICE] Sharing password through secure channel (not via email!)")
    print(f"[ALICE] Message sent!")


def bob_receive_message(encrypted_file):
    # Bob receives the encrypted file from Alice
    print(f"\n[BOB] Received encrypted file from Alice: {encrypted_file}")
    
    if os.path.exists(encrypted_file):
        file_size = os.path.getsize(encrypted_file)
        print(f"[BOB] File size: {file_size} bytes")
        print(f"[BOB] File is encrypted (binary data)")
        return True
    else:
        print(f"[BOB] Error: File not found!")
        return False


def bob_decrypt_message(encrypted_file, output_file, password):
    # Bob decrypts the message using the password Alice shared
    print(f"\n[BOB] Decrypting message from Alice...")
    print(f"[BOB] Using password: {'*' * len(password)} (hidden)")
    
    try:
        # OpenSSL decryption command
        cmd = [
            'openssl', 'enc', '-aes-128-cbc',
            '-d',              # Decrypt mode
            '-salt',
            '-pbkdf2',
            '-in', encrypted_file,
            '-out', output_file,
            '-pass', f'pass:{password}'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[BOB] Decryption successful!")
            print(f"[BOB] Decrypted file: {output_file}")
            return True
        else:
            print(f"[BOB] Decryption failed!")
            print(f"[BOB] Wrong password or corrupted file")
            return False
            
    except Exception as e:
        print(f"[BOB] Error during decryption: {e}")
        return False


def bob_read_message(decrypted_file):
    # Bob reads the decrypted message
    print(f"\n[BOB] Reading decrypted message...")
    print("*" * 70)
    
    try:
        with open(decrypted_file, 'r', encoding='utf-8') as f:
            message = f.read()
            print(message[:300])  # Show first 300 characters
            if len(message) > 300:
                print("... (message continues)")
        print("*" * 70)
        return message
    except Exception as e:
        print(f"[BOB] Error reading message: {e}")
        return None


def bob_verify_message(original_file, decrypted_file):
    # Bob verifies the message integrity
    print(f"\n[BOB] Verifying message integrity...")
    
    try:
        with open(original_file, 'rb') as f1:
            original = f1.read()
        with open(decrypted_file, 'rb') as f2:
            decrypted = f2.read()
        
        if original == decrypted:
            print(f"[BOB] Message integrity verified!")
            print(f"[BOB] Original and decrypted files are identical")
            return True
        else:
            print(f"[BOB] Message integrity check failed!")
            return False
    except Exception as e:
        print(f"[BOB] Error: {e}")
        return False

print("*" * 70)
print("  TASK 3: OPENSSL ENCRYPTION AND DECRYPTION")
print("  Alice (Sender) → Bob (Receiver)")
print("*" * 70)

# Choose password type: fixed or random
print("\n[SYSTEM] Password Options:")
print("[SYSTEM] 1. Fixed password (easier to share)")
print("[SYSTEM] 2. Random password (more secure)")

use_random = False  # Change to True to use random password

if use_random:
    password = generate_random_password(20)
    print(f"\n[SYSTEM] Generated random password: {password}")
    print(f"[SYSTEM] (In real scenario, share this securely with Bob)")
else:
    password = "assignment_password_123"
    print(f"\n[SYSTEM] Using fixed password: {password}")

print("\n" + "*" * 70)
print("SCENARIO 1: ENGLISH MESSAGE")
print("*" * 70)

# Alice creates and encrypts message
eng_original = "en_message.txt"
eng_encrypted = "en_encrypted.bin"

alice_create_message(english_text, eng_original)
alice_encrypt_message(eng_original, eng_encrypted, password)
alice_send_to_bob(eng_encrypted, password)

# Bob receives and decrypts
bob_receive_message(eng_encrypted)
eng_decrypted = "en_decrypted.txt"

if bob_decrypt_message(eng_encrypted, eng_decrypted, password):
    bob_read_message(eng_decrypted)
    bob_verify_message(eng_original, eng_decrypted)

# German version
print("\n\n" + "*" * 70)
print("SCENARIO 2: GERMAN MESSAGE")
print("*" * 70)

# Alice creates and encrypts German message
de_original = "de_message.txt"
de_encrypted = "de_encrypted.bin"

alice_create_message(german_text, de_original)
alice_encrypt_message(de_original, de_encrypted, password)
alice_send_to_bob(de_encrypted, password)

# Bob receives and decrypts
bob_receive_message(de_encrypted)
de_decrypted = "de_decrypted.txt"

if bob_decrypt_message(de_encrypted, de_decrypted, password):
    bob_read_message(de_decrypted)
    bob_verify_message(de_original, de_decrypted)


print("\n\n" + "*" * 70)
print("SUMMARY")
print("*" * 70)
print("\n Alice successfully encrypted both messages")
print("Bob successfully decrypted both messages")
print("\nOpenSSL AES-128-CBC provides strong security!")
print("Only Bob with correct password can read the messages")

print("\n" + "*" * 70)
print("VIEWING ENCRYPTED FILES (HEXADECIMAL FORMAT)")
print("*" * 70)

# View English encrypted file
print("\n[VIEW] English Encrypted File: en_encrypted.bin")
with open("en_encrypted.bin", 'rb') as f:
    data = f.read()
    print(f"[VIEW] Total size: {len(data)} bytes")
    print(f"[VIEW] First 128 bytes in hex:")
    
    # Display in neat rows of 16 bytes
    for i in range(0, min(128, len(data)), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        print(f"       {i:04x}: {hex_part}")

# View German encrypted file
print("\n[VIEW] German Encrypted File: de_encrypted.bin")
with open("de_encrypted.bin", 'rb') as f:
    data = f.read()
    print(f"[VIEW] Total size: {len(data)} bytes")
    print(f"[VIEW] First 128 bytes in hex:")
    
    for i in range(0, min(128, len(data)), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
        print(f"       {i:04x}: {hex_part}")
        
        
        
        
        