from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import sys

def decrypt(cipher_file, plain_file, priv_key_file, password=None):
    password_bytes = password.encode('utf-8') if (password != None) else None
    with open(priv_key_file, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password_bytes,
            backend=default_backend()
        )

    with open(cipher_file, 'rb') as f:
        ciphertext = f.read()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )

    with open(plain_file, 'wb') as f:
        f.write(plaintext)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python decrypt.py <cipher_file> <plain_file> <priv_key_file>")
        sys.exit(1)

    cipher_file = sys.argv[1]
    plain_file = sys.argv[2]
    priv_key_file = sys.argv[3]

    decrypt(cipher_file, plain_file, priv_key_file)
    print(f"Decryption complete. Plain text saved to {plain_file}")

# Usage: 
# python3 decrypt.py cipher.bin plain_1.txt priv.pem 
