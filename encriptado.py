import hashlib
import base64
import uuid

def generate_salt():
    """Generates a new random salt."""
    return base64.urlsafe_b64encode(uuid.uuid4().bytes)

def encrypt_password(password, salt):
    """Encrypts the password using SHA-512 and a salt."""
    t_sha = hashlib.sha512()
    t_sha.update(password.encode('utf-8') + salt)
    return base64.urlsafe_b64encode(t_sha.digest()).decode('utf-8')

def verify_password(stored_password, provided_password, salt):
    """Verifies the provided password against the stored hashed password."""
    encrypted = encrypt_password(provided_password, salt)
    return encrypted == stored_password

if __name__ == "__main__":
    password = 'test_password'
    salt = generate_salt()
    encrypted = encrypt_password(password, salt)
    print(f"Encrypted: {encrypted}")
    print(f"Salt: {salt.decode('utf-8')}")

    is_valid = verify_password(encrypted, password, salt)
    print(f"Password is valid: {is_valid}")
