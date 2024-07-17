import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def read_private_key(file_path, password = None):
    try:
        password_bytes = password.encode('utf-8') if (password != None) else None
        with open(file_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password_bytes,
                backend=default_backend()
            )
        return private_key
    except Exception as e:
        print(f"Error reading private key: {e}")
        return None

def read_public_key(file_path):
    try:
        with open(file_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        print(f"Error reading public key: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python main.py <private_key_file> <public_key_file>")
        sys.exit(1)

    private_key_file = sys.argv[1]
    public_key_file = sys.argv[2]

    private_key = read_private_key(private_key_file)
    public_key = read_public_key(public_key_file)

    if private_key:
        print("\nPrivate Key Components:")
        print(f"Modulus (n): {private_key.private_numbers().public_numbers.n}")
        print(f"Public Exponent (e): {private_key.private_numbers().public_numbers.e}")
        print(f"Private Exponent (d): {private_key.private_numbers().d}")
        print(f"p: {private_key.private_numbers().p}")
        print(f"q: {private_key.private_numbers().q}")
        print(f"d mod (p-1): {private_key.private_numbers().dmp1}")
        print(f"d mod (q-1): {private_key.private_numbers().dmq1}")
        print(f"coefficient e^-1 mod p: {private_key.private_numbers().iqmp}")

    if public_key:
        print("\nPublic Key Components:")
        print(f"Modulus (n): {public_key.public_numbers().n}")
        print(f"Public Exponent (e): {public_key.public_numbers().e}")

# Usage: 
# python3 read_components.py priv.pem pub.pem

