from Crypto.Cipher import AES
from typing import Optional


def aes_gcm_encrypt(key: bytes, data: bytes, nonce: Optional[bytes] = None) -> bytes:
    """
    Encrypts data using AES-GCM. If nonce is None, a random one is generated.
    Returns: nonce (16b) + tag (16b) + ciphertext
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    enc, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + enc


def aes_gcm_decrypt(key: bytes, data: bytes) -> bytes:
    """
    Decrypts data using AES-GCM. Expects: nonce (16b) + tag (16b) + ciphertext
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=data[:16])
    return cipher.decrypt_and_verify(data[32:], data[16:32]) 