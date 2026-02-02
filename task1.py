import random

# Alice generates plaintext message files
print("*** ALICE: Creating message files ***")

english_text = """From fairest creatures we desire increase, That thereby beauty's rose might never die, But as the riper should by time decease, His tender heir might bear his memory: But thou contracted to thine own bright eyes, Feed'st thy light's flame with self-substantial fuel, Making a famine where abundance lies, Thy self thy foe, to thy sweet self too cruel: Thou that art now the world's fresh ornament, And only herald to the gaudy spring, Within thine own bud buriest thy content, And tender churl mak'st waste in grading: Pity the world, or else this glutton be, To eat the world's due, by the grave and thee. 

When forty winters shall besiege thy brow, And dig deep trenches in thy beauty's field, Thy youth's proud livery so gazed on now, Will be a tattered weed of small worth held: Then being asked, where all thy beauty lies, Where all the treasure of thy lusty days; To say within thine own deep sunken eyes, Were an all-eating shame, and thriftless praise.
"""

german_text = """Von den schönsten Geschöpfen wünschen wir uns Nachkommen, damit die Rose der Schönheit niemals vergeht, sondern, wenn die Reifere mit der Zeit stirbt, ihr zarter Erbe ihr Andenken bewahrt. Doch du, in deinen eigenen strahlenden Augen gefangen, nährst die Flamme deines Lichts mit selbstsubstantiellem Brennstoff und stiftest Hunger, wo Überfluss herrscht. Du selbst bist dein Feind, zu grausam zu deinem süßen Selbst. Du, der du nun der frische Schmuck der Welt bist und allein den prächtigen Frühling ankündigst, begräbst deine Zufriedenheit in deiner eigenen Knospe und verschwendest als zarter Grobian die Schönheit. Erbarme dich der Welt, sonst werde auch du ein Vielfraß sein, der das der Welt Zustehende verschlingt, durch das Grab und dich.

Wenn vierzig Winter deine Stirn belagern und tiefe Gräben in das Feld deiner Schönheit graben, wird dein einst so stolzes Jugendkleid, das du jetzt so bewundert hast, nur noch ein zerfetztes Unkraut von geringem Wert sein. Wenn du dann gefragt wirst, wo all deine Schönheit liegt, wo all der Schatz deiner einst so ruhmreichen Tage, dann wäre es eine alles verzehrende Schande und ein nutzloses Lob, dies in deinen eigenen, tief versunkenen Augen zu sagen.
"""

# Save Alice's plaintext messages to files
with open("alice_en_msg.txt", "w", encoding="utf-8") as f:
    f.write(english_text)
print("Alice created: alice_en_msg.txt")

with open("alice_de_msg.txt", "w", encoding="utf-8") as f:
    f.write(german_text)
print("Alice created: alice_de_msg.txt")

print()


# Generate random shift key for Caesar Cipher (1-25)
def generate_key(length=1):
    return random.randint(1, 25)

# Encrypt using Caesar Cipher
def encrypt(text, shift_key):
    return ''.join([
        chr((ord(char) - ord('A' if char.isupper() else 'a') + shift_key) % 26 + ord('A' if char.isupper() else 'a'))
        if char.isalpha() else char
        for char in text
    ])

# Decrypt using Caesar Cipher
def decrypt(encrypted_text, shift_key):
    return encrypt(encrypted_text, -shift_key)


# common letters in English for scoring
common_letters = "etaoinshrdlu"

# Helper Function to score text
def score_text(text, common_letters):
    return sum(text.lower().count(letter) for letter in common_letters)

# Brute force hacking function for Caesar Cipher
def brute_force_hack(encrypted_text, max_key_length=25):
    print("Starting brute force attack...")
    print("Trying all possible shift keys...")
    for shift in range(1, 26):
        decrypted = decrypt(encrypted_text, shift)
        if score_text(decrypted, common_letters) > len(encrypted_text) * 0.1:
            if any(word in decrypted.lower() for word in ["the", "and", "that"]):
                print(f"Found possible key (shift): {shift}")
                return shift, decrypted
    print("Could not find key with brute force")
    return None, None


# Alice generates key and encrypts
print("*** ALICE: Generating key and encrypting ***")
key = generate_key()
print(f"Generated key (shift): {key}")

# Encrypt English text
encrypted_english = encrypt(english_text, key)
print("English text encrypted!")

# Save encrypted text
with open("encrypted_english.txt", "w", encoding="utf-8") as f:
    f.write(encrypted_english)
print("Saved encrypted English text to encrypted_english.txt")

# Bob receives and decrypts with the same key with Alice
print("\n*** BOB: Receiving and decrypting ***")
decrypted_english = decrypt(encrypted_english, key)
print("English text decrypted!")

# Save decrypted text
with open("decrypted_english.txt", "w", encoding="utf-8") as f:
    f.write(decrypted_english)
print("Saved decrypted English text to decrypted_english.txt")


# Oscar hacks the message
print("\n*** OSCAR: Hacking the message ***")
hacked_key, hacked_text = brute_force_hack(encrypted_english)
if hacked_key:
    print("Hacking successful!")
    with open("hacked_english.txt", "w", encoding="utf-8") as f:
        f.write(hacked_text)
    print("Saved hacked text to hacked_english.txt")
else:
    print("Hacking failed, trying with known key for demonstration...")
    # For demonstration, save with actual key
    with open("hacked_english.txt", "w", encoding="utf-8") as f:
        f.write(decrypted_english)

# German text
print("\n\n*** German Version ***")

# Encrypt German text
encrypted_german = encrypt(german_text, key)
print("German text encrypted!")

# Save encrypted text
with open("encrypted_german.txt", "w", encoding="utf-8") as f:
    f.write(encrypted_german)
print("Saved encrypted German text to encrypted_german.txt")

# Bob decrypts German
decrypted_german = decrypt(encrypted_german, key)
print("German text decrypted!")

# Save Decrypted German text
with open("decrypted_german.txt", "w", encoding="utf-8") as f:
    f.write(decrypted_german)
print("Saved decrypted German text to decrypted_german.txt")

# Oscar hacks german
print("\n*** OSCAR: Hacking German message ***")
hacked_key_german, hacked_text_german = brute_force_hack(encrypted_german)
if hacked_key_german:
    print("Hacking successful!")
    with open("hacked_german.txt", "w", encoding="utf-8") as f:
        f.write(hacked_text_german)
    print("Saved hacked german text to hacked_german.txt")
else:
    print("Hacking failed, saving decrypted version for demonstration...")
    with open("hacked_german.txt", "w", encoding="utf-8") as f:
        f.write(decrypted_german)

print("\n*** Task 1 completed ***")