import bcrypt

#pip install bcrypt

def encrypt_password(password):
    """Encrypts the password using bcrypt (includes salt generation)."""
    # bcrypt genera automáticamente la salt y la incluye en el hash
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode('utf-8')

def verify_password(stored_password, provided_password):
    """Verifies the provided password against the stored hashed password."""
    password_bytes = provided_password.encode('utf-8')
    stored_bytes = stored_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, stored_bytes)

if __name__ == "__main__":
    password = 'test_password'
    
    # Encriptar contraseña (bcrypt maneja la salt internamente)
    encrypted = encrypt_password(password)
    print(f"Encrypted: {encrypted}")
    
    # Verificar contraseña
    is_valid = verify_password(encrypted, password)
    print(f"Password is valid: {is_valid}")
    
    # Probar con contraseña incorrecta
    is_invalid = verify_password(encrypted, "wrong_password")
    print(f"Wrong password is valid: {is_invalid}")
