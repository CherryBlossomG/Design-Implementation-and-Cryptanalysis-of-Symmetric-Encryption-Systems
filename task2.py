import random


# Read the English text file of alice
with open("alice_en_msg.txt", "r", encoding="utf-8") as f:
    english_text = f.read()

# Read the German text file
with open("alice_de_msg.txt", "r", encoding="utf-8") as f:
    german_text = f.read()


# S-Box for AES
# Got this from AES specification document (FIPS 197)
# This is 16x16 table = 256 values
s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Inverse S-Box
inv_s_box = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Generate 128-bit (16 bytes) random key
# 128 bits = 16 bytes, each byte is 0-255
def generate_key():
    key = []
    for i in range(16):
        key.append(random.randint(0, 255))
    return key

# Helper function: Convert 1D list (16 bytes) to 4x4 matrix
# AES state is stored in column-major order
# state[0:4] is column 0, state[4:8] is column 1, state[8:12] is column 2, state[12:16] is column 3
# Matrix representation: matrix[row][col]
def list_to_matrix(state):
    matrix = [[0 for _ in range(4)] for _ in range(4)]
    for col in range(4):
        for row in range(4):
            # Column-major: state[col*4 + row] -> matrix[row][col]
            matrix[row][col] = state[col*4 + row]
    return matrix

# Helper function: Convert 4x4 matrix to 1D list (16 bytes)
def matrix_to_list(matrix):
    state = [0] * 16
    for col in range(4):
        for row in range(4):
            # Column-major: matrix[row][col] -> state[col*4 + row]
            state[col*4 + row] = matrix[row][col]
    return state

# SubBytes transformation
# Replaces each byte with value from S-box
# State can be represented as 4x4 matrix (more intuitive)
def sub_bytes(state):
    # Convert 1D list to 4x4 matrix for easier understanding
    s = list_to_matrix(state)
    
    # Apply S-box substitution to each byte in the matrix
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]
    
    # Convert back to 1D list
    return matrix_to_list(s)

# Inverse SubBytes
def inv_sub_bytes(state):
    # Convert 1D list to 4x4 matrix
    s = list_to_matrix(state)
    
    # Apply inverse S-box substitution to each byte
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]
    
    # Convert back to 1D list
    return matrix_to_list(s)


# ShiftRows transformation
# State is 16 bytes arranged in 4x4 matrix (column-major order)
# Row 0: no shift
# Row 1: shift left by 1
# Row 2: shift left by 2
# Row 3: shift left by 3
def shift_rows(state):
    new_state = [0] * 16
    # Row 0: indices 0, 4, 8, 12 - no shift
    new_state[0] = state[0]
    new_state[1] = state[5]   # Row 1: shift left by 1
    new_state[2] = state[10]  # Row 2: shift left by 2
    new_state[3] = state[15]  # Row 3: shift left by 3
    new_state[4] = state[4]
    new_state[5] = state[9]
    new_state[6] = state[14]
    new_state[7] = state[3]
    new_state[8] = state[8]
    new_state[9] = state[13]
    new_state[10] = state[2]
    new_state[11] = state[7]
    new_state[12] = state[12]
    new_state[13] = state[1]
    new_state[14] = state[6]
    new_state[15] = state[11]
    return new_state



# Inverse ShiftRows
def inv_shift_rows(state):
    new_state = [0] * 16
    new_state[0] = state[0]
    new_state[1] = state[13]
    new_state[2] = state[10]
    new_state[3] = state[7]
    new_state[4] = state[4]
    new_state[5] = state[1]
    new_state[6] = state[14]
    new_state[7] = state[11]
    new_state[8] = state[8]
    new_state[9] = state[5]
    new_state[10] = state[2]
    new_state[11] = state[15]
    new_state[12] = state[12]
    new_state[13] = state[9]
    new_state[14] = state[6]
    new_state[15] = state[3]
    return new_state

# Galois field multiplication
# GF(2^8) arithmetic
# uses irreducible polynomial 0x11b
def gf_multiply(a, b):
    result = 0
    for i in range(8):
        if b & 1:
            result ^= a
        a <<= 1
        # Reduce modulo irreducible polynomial if overflow
        if a & 0x100:
            a ^= 0x11b  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return result & 0xff

# MixColumns transformation
def mix_columns(state):
    new_state = [0] * 16
    for i in range(4):
        col = state[i*4:(i+1)*4]
        new_state[i*4] = gf_multiply(2, col[0]) ^ gf_multiply(3, col[1]) ^ col[2] ^ col[3]
        new_state[i*4+1] = col[0] ^ gf_multiply(2, col[1]) ^ gf_multiply(3, col[2]) ^ col[3]
        new_state[i*4+2] = col[0] ^ col[1] ^ gf_multiply(2, col[2]) ^ gf_multiply(3, col[3])
        new_state[i*4+3] = gf_multiply(3, col[0]) ^ col[1] ^ col[2] ^ gf_multiply(2, col[3])
    return new_state

# Inverse MixColumns
def inv_mix_columns(state):
    new_state = [0] * 16
    for i in range(4):
        col = state[i*4:(i+1)*4]
        new_state[i*4] = gf_multiply(14, col[0]) ^ gf_multiply(11, col[1]) ^ gf_multiply(13, col[2]) ^ gf_multiply(9, col[3])
        new_state[i*4+1] = gf_multiply(9, col[0]) ^ gf_multiply(14, col[1]) ^ gf_multiply(11, col[2]) ^ gf_multiply(13, col[3])
        new_state[i*4+2] = gf_multiply(13, col[0]) ^ gf_multiply(9, col[1]) ^ gf_multiply(14, col[2]) ^ gf_multiply(11, col[3])
        new_state[i*4+3] = gf_multiply(11, col[0]) ^ gf_multiply(13, col[1]) ^ gf_multiply(9, col[2]) ^ gf_multiply(14, col[3])
    return new_state

# AddRoundKey
def add_round_key(state, round_key):
    new_state = []
    for i in range(16):
        new_state.append(state[i] ^ round_key[i])
    return new_state

# Key expansion
# Real AES key expansion is really complicated with rotations and S-box
# using same key for all rounds to keep it simpler
def expand_key(key):
    round_keys = []
    for round_num in range(11):  # 10 rounds + 1 initial
        round_keys.append(key[:])  # Copy key
    return round_keys

# AES encryption
# Follows AES-128 specification (10 rounds)
# Each round consists of 4 layers: SubBytes, ShiftRows, MixColumns, AddRoundKey
# Last round (round 10) does NOT have MixColumns
def aes_encrypt(plaintext, key):
    # Pad plaintext to multiple of 16 bytes (block size)
    # Using PKCS#7 padding - pad with value equal to padding length
    padding = 16 - (len(plaintext) % 16)
    if padding == 16:
        padding = 0  # No padding needed if already multiple of 16
    else:
        plaintext += bytes([padding] * padding)
    
    round_keys = expand_key(key)
    ciphertext = []
    
    # Process each 16-byte block
    for block_start in range(0, len(plaintext), 16):
        block = list(plaintext[block_start:block_start+16])
        
        # Initial round: AddRoundKey only (using round key 0)
        block = add_round_key(block, round_keys[0])
        
        # Rounds 1-9: Each round has 4 layers
        # Layer 1: SubBytes (byte substitution)
        # Layer 2: ShiftRows (row shifting)
        # Layer 3: MixColumns (column mixing)
        # Layer 4: AddRoundKey (key addition)
        for round_num in range(1, 10):
            # Layer 1: Byte Substitution
            block = sub_bytes(block)
            # Layer 2: Shift Rows
            block = shift_rows(block)
            # Layer 3: Mix Columns
            block = mix_columns(block)
            # Layer 4: Add Round Key
            block = add_round_key(block, round_keys[round_num])
        
        # Final round (round 10): Only 3 layers (NO MixColumns!)
        # Layer 1: Byte Substitution
        block = sub_bytes(block)
        # Layer 2: Shift Rows
        block = shift_rows(block)
        # Layer 3: Add Round Key (NO MixColumns in final round)
        block = add_round_key(block, round_keys[10])
        
        ciphertext.extend(block)
    
    return bytes(ciphertext)

# AES decryption
# Reverse of encryption - operations done in reverse order
# Each round consists of 4 inverse layers: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
# Last round (round 0) does NOT have InvMixColumns
def aes_decrypt(ciphertext, key):
    round_keys = expand_key(key)
    plaintext = []
    
    # Process each 16-byte block
    for block_start in range(0, len(ciphertext), 16):
        block = list(ciphertext[block_start:block_start+16])
        
        # Initial round: AddRoundKey only (using round key 10)
        block = add_round_key(block, round_keys[10])
        
        # Rounds 9-1 (reverse order): Each round has 4 inverse layers
        # Layer 1: InvShiftRows (inverse row shifting)
        # Layer 2: InvSubBytes (inverse byte substitution)
        # Layer 3: Add Round Key
        # Layer 4: InvMixColumns (inverse column mixing)
        for round_num in range(9, 0, -1):
            # Layer 1: Inverse Shift Rows
            block = inv_shift_rows(block)
            # Layer 2: Inverse Byte Substitution
            block = inv_sub_bytes(block)
            # Layer 3: Add Round Key
            block = add_round_key(block, round_keys[round_num])
            # Layer 4: Inverse Mix Columns
            block = inv_mix_columns(block)
        
        # Final round (round 0): Only 3 layers (NO InvMixColumns!)
        # Layer 1: Inverse Shift Rows
        block = inv_shift_rows(block)
        # Layer 2: Inverse Byte Substitution
        block = inv_sub_bytes(block)
        # Layer 3: Add Round Key (NO InvMixColumns in final round)
        block = add_round_key(block, round_keys[0])
        
        plaintext.extend(block)
    
    # Remove padding
    # Last byte tells us how much padding was added
    padding = plaintext[-1]
    # Check if padding is valid (1-16)
    if padding > 0 and padding <= 16:
        plaintext = plaintext[:-padding]
    # If no padding, leave as is
    
    return bytes(plaintext)


print("\n*** AES Encryption System ***")

# Alice generates key and encrypts
print("\n*** ALICE: Generating key and encrypting ***")
key = generate_key()
print(f"Generated 128-bit key: {[hex(k) for k in key]}")

# Encrypt English text
print("\n*** English Text ***")
english_bytes = english_text.encode('utf-8')
print(f"Original English text length: {len(english_bytes)} bytes")

encrypted_english = aes_encrypt(english_bytes, key)
print("English text encrypted!")

# Save encrypted text
f = open("aes_encrypted_en.txt", "wb")
f.write(encrypted_english)
f.close()
print("Saved encrypted English text to aes_encrypted_english.txt")

# Bob receives and decrypts with the same key with Alice
print("\n*** BOB: Receiving and decrypting ***")
decrypted_english_bytes = aes_decrypt(encrypted_english, key)
decrypted_english = decrypted_english_bytes.decode('utf-8')
print("English text decrypted!")

# Save decrypted text
f = open("aes_decrypted_en.txt", "w", encoding="utf-8")
f.write(decrypted_english)
f.close()
print("Saved decrypted English text to aes_decrypted_en.txt")

# Verify decryption
if decrypted_english == english_text:
    print("Decryption successful! English text matches original.")
else:
    print("Warning: Decrypted English text does not match original.")

# Oscar attempts to hack the encrypted English text (just print message only)
print("\n*** OSCAR: Attempting to hack the encrypted English message using brute force... ***")
print("Oscar FAILED to hack the system. AES using brute force is impossible.")

# German text
print("\n\n*** German Version ***")

# Encrypt German text
print("\n*** German Text ***")
german_bytes = german_text.encode('utf-8')
print(f"Original German text length: {len(german_bytes)} bytes")

encrypted_german = aes_encrypt(german_bytes, key)
print("German text encrypted!")

# Save encrypted text
f = open("aes_encrypted_de.txt", "wb")
f.write(encrypted_german)
f.close()
print("Saved encrypted German text to aes_encrypted_de.txt")

# Bob decrypts German
decrypted_german_bytes = aes_decrypt(encrypted_german, key)
decrypted_german = decrypted_german_bytes.decode('utf-8')
print("German text decrypted!")

# Save Decrypted German text
f = open("aes_decrypted_de.txt", "w", encoding="utf-8")
f.write(decrypted_german)
f.close()
print("Saved decrypted German text to aes_decrypted_de.txt")

# Verify decryption
if decrypted_german == german_text:
    print("Decryption successful! German text matches original.")
else:
    print("Warning: Decrypted German text does not match original.")


# Oscar attempts to hack the encrypted German text
print("\n*** OSCAR: Attempting to hack the encrypted German message using brute force... ***")
print("Oscar FAILED to hack the system. AES using brute force is impossible.")
print("\n*** Task 2 completed ***")