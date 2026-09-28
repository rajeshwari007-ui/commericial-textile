import hashlib
import os
import re
import base64
import time
import struct

def hash_password(password: str) -> str:
    """
    Hashes a password using the memory-hard scrypt algorithm.
    Returns a string in the format: scrypt$n$r$p$salt_hex$hash_hex
    """
    salt = os.urandom(16)
    n = 16384
    r = 8
    p = 1
    dk = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"

def verify_password(stored_hash: str, password: str) -> bool:
    """
    Verifies a password against a stored scrypt hash format.
    """
    try:
        parts = stored_hash.split('$')
        if len(parts) != 6 or parts[0] != 'scrypt':
            return False
        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
        salt = bytes.fromhex(parts[4])
        expected_hash = bytes.fromhex(parts[5])
        
        dk = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p)
        return dk == expected_hash
    except Exception:
        return False

def is_password_complex(password: str) -> bool:
    """
    Validates password complexity:
    - Minimum length of 8 characters.
    - At least one uppercase letter.
    - At least one lowercase letter.
    - At least one digit.
    - At least one special character.
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def generate_totp_secret() -> str:
    """
    Generates a random 16-character Base32 secret string for TOTP.
    """
    # 10 bytes = 80 bits, which formats to exactly 16 characters in base32
    random_bytes = os.urandom(10)
    return base64.b32encode(random_bytes).decode('utf-8')

def verify_totp(secret: str, token: str, window: int = 1) -> bool:
    """
    Verifies a 6-digit TOTP code against a Base32 secret.
    Allows clock drift via the window parameter.
    """
    if not secret or not token:
        return False
        
    try:
        token = str(token).strip()
        if len(token) != 6 or not token.isdigit():
            return False
            
        secret = secret.replace(" ", "").upper()
        # Add base32 padding if missing
        missing_padding = len(secret) % 8
        if missing_padding:
            secret += '=' * (8 - missing_padding)
            
        key = base64.b32decode(secret)
        curr_time = int(time.time()) // 30
        
        for i in range(-window, window + 1):
            t = curr_time + i
            msg = struct.pack(">Q", t)
            hmac_hash = hmac_new(key, msg, hashlib.sha1)
            offset = hmac_hash[-1] & 0x0F
            code = (struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF) % 1000000
            if f"{code:06d}" == token:
                return True
        return False
    except Exception:
        return False

def hmac_new(key: bytes, msg: bytes, digestmod) -> bytes:
    """
    Custom hmac implementation to ensure standard python library availability.
    """
    import hmac
    return hmac.new(key, msg, digestmod).digest()
