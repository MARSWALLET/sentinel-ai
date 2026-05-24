# ============================================
# SentinelAI - Cryptography Utilities
# ============================================
"""
Encryption/decryption utilities for securing API keys and sensitive data.
Uses AES-256-GCM for authenticated encryption.
"""

import base64
import logging
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


def _get_key_bytes(key: str) -> bytes:
    """
    Convert a hex string key to bytes.
    
    Args:
        key: Hex-encoded key string (must be 32 bytes for AES-256)
        
    Returns:
        Key bytes
    """
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        # If not hex, hash it to get 32 bytes
        import hashlib
        key_bytes = hashlib.sha256(key.encode()).digest()
    
    # Ensure 32 bytes for AES-256
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b"\0")
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    
    return key_bytes


def encrypt_text(plaintext: str, key: str) -> str:
    """
    Encrypt text using AES-256-GCM.
    
    Args:
        plaintext: Text to encrypt
        key: Encryption key (hex string)
        
    Returns:
        Base64-encoded ciphertext with nonce
    """
    try:
        key_bytes = _get_key_bytes(key)
        
        # Generate random nonce (12 bytes recommended for GCM)
        nonce = os.urandom(12)
        
        # Create cipher and encrypt
        aesgcm = AESGCM(key_bytes)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        
        # Combine nonce + ciphertext and encode
        combined = nonce + ciphertext
        encoded = base64.b64encode(combined).decode("utf-8")
        
        return encoded
        
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise


def decrypt_text(ciphertext: str, key: str) -> str:
    """
    Decrypt text encrypted with AES-256-GCM.
    
    Args:
        ciphertext: Base64-encoded ciphertext with nonce
        key: Encryption key (hex string)
        
    Returns:
        Decrypted plaintext
    """
    try:
        key_bytes = _get_key_bytes(key)
        
        # Decode from base64
        combined = base64.b64decode(ciphertext)
        
        # Extract nonce (first 12 bytes) and ciphertext
        nonce = combined[:12]
        encrypted_data = combined[12:]
        
        # Decrypt
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
        
        return plaintext.decode("utf-8")
        
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key using SHA-256.
    
    Args:
        api_key: API key to hash
        
    Returns:
        Hex-encoded SHA-256 hash
    """
    import hashlib
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_random_key(length: int = 32) -> str:
    """
    Generate a random encryption key.
    
    Args:
        length: Key length in bytes (default 32 for AES-256)
        
    Returns:
        Hex-encoded random key
    """
    return os.urandom(length).hex()


def generate_api_key(prefix: str = "sent") -> str:
    """
    Generate a random API key.
    
    Args:
        prefix: Key prefix
        
    Returns:
        Random API key string
    """
    import secrets
    token = secrets.token_urlsafe(32)
    return f"{prefix}_{token}"