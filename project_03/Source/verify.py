# verify.py
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys

def verify(message_file, signature_file, pub_key_file):
    with open(pub_key_file, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    with open(message_file, 'rb') as f:
        message = f.read()

    with open(signature_file, 'rb') as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature verified Successfully.")
    except KeyError as e:
        print(f"Signature verification failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python verify.py <message_file> <signature_file> <pub_key_file>")
        sys.exit(1)

    message_file = sys.argv[1]
    signature_file = sys.argv[2]
    pub_key_file = sys.argv[3]

    verify(message_file, signature_file, pub_key_file)

# Usage:
# python3 verify.py mess.txt signature.bin pub.pem 