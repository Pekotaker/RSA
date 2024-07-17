# encrypt.py
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys

def encrypt(plain_file, cipher_file, pub_key_file):
    with open(pub_key_file, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )   

    with open(plain_file, 'rb') as f:
        plaintext = f.read()
        
    ciphertext = public_key.encrypt(
        plaintext,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    with open(cipher_file, 'wb') as f:
        f.write(ciphertext)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python encrypt.py <plain_file> <cipher_file> <pub_key_file>")
        sys.exit(1)

    plain_file = sys.argv[1]
    cipher_file = sys.argv[2]
    pub_key_file = sys.argv[3]

    encrypt(plain_file, cipher_file, pub_key_file)
    print(f"Encryption complete. Cipher saved to {cipher_file}")

# Usage: 
# python3 encrypt.py plain_0.txt cipher.bin pub.pem
