from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys

def sign(message_file, signature_file, priv_key_file):
    with open(priv_key_file, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Add password if applicable
            backend=default_backend()
        )

    with open(message_file, 'rb') as f:
        message = f.read()

    signature = private_key.sign( 
        message, 
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    with open(signature_file, 'wb') as f:
        f.write(signature)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python sign.py <message_file> <signature_file> <priv_key_file>")
        sys.exit(1)

    message_file = sys.argv[1]
    signature_file = sys.argv[2]
    priv_key_file = sys.argv[3]

    sign(message_file, signature_file, priv_key_file)
    print(f"Signature generated and saved to {signature_file}")

# Usage:
# python3 sign.py mess.txt signature.bin priv.pem 