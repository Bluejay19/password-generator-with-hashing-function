import random
import string
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Function to generate a random password
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# Function to generate a random passphrase
def generate_passphrase(words=4):
    # Using a simple list of words for demonstration
    word_list = ["apple", "banana", "cherry", "date", "elderberry"]
    return ' '.join(random.choice(word_list) for _ in range(words))

# Function to hash a password using the specified algorithm
def hash_password(password, algorithm='sha256'):
    h = hashlib.new(algorithm)
    h.update(password.encode('utf-8'))
    return h.hexdigest()

# Function to generate a random hash
def generate_random_hash(algorithm='sha256'):
    random_data = get_random_bytes(16)
    h = hashlib.new(algorithm)
    h.update(random_data)
    return h.hexdigest()

# Function to encrypt data using AES encryption
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

# Function to decrypt AES-encrypted data
def decrypt_data(enc_data, key):
    enc_data = base64.b64decode(enc_data)
    nonce = enc_data[:16]
    ciphertext = enc_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

if __name__ == "__main__":
    # Generate a random password
    password = generate_password()
    print(f"Generated Password: {password}")
    
    # Generate a random passphrase
    passphrase = generate_passphrase()
    print(f"Generated Passphrase: {passphrase}")
    
    # Hash the password using SHA-256
    password_hash = hash_password(password)
    print(f"SHA-256 Hash: {password_hash}")
    
    # Generate a random hash
    random_hash = generate_random_hash()
    print(f"Random Hash: {random_hash}")
    
    # Define a key for AES encryption (must be 16, 24, or 32 bytes long)
    key = get_random_bytes(24)
    data = "This is a secret message."
    
    # Encrypt the data using AES
    enc_data = encrypt_data(data, key)
    print(f"Encrypted Data: {enc_data}")
    
    # Decrypt the encrypted data
    dec_data = decrypt_data(enc_data, key)
    print(f"Decrypted Data: {dec_data}")
