"""
psi_core/crypto_utils.py
Helper functions: EC point serialization, AES-GCM label encryption.
"""

import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─── AES-GCM Label Encryption ────────────────────────────────────────────────

def _get_key_bytes(key_hex: str) -> bytes:
    """Convert hex key string to 32 bytes. Pads/truncates to 32 bytes."""
    try:
        raw = bytes.fromhex(key_hex)
    except ValueError:
        raw = key_hex.encode("utf-8")
    # Ensure exactly 32 bytes
    if len(raw) >= 32:
        return raw[:32]
    return raw.ljust(32, b'\x00')


def encrypt_label(plaintext: str, key_hex: str) -> str:
    """
    AES-GCM encryption of a plaintext string.
    Returns a base64-encoded JSON string: {"nonce": "...", "ciphertext": "..."}
    """
    key = _get_key_bytes(key_hex)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    payload = {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ct).decode("utf-8"),
    }
    return base64.b64encode(json.dumps(payload).encode()).decode("utf-8")


def decrypt_label(ciphertext_b64: str, key_hex: str) -> str:
    """
    AES-GCM decryption. Accepts the output of encrypt_label().
    Returns the original plaintext string.
    """
    key = _get_key_bytes(key_hex)
    payload = json.loads(base64.b64decode(ciphertext_b64).decode("utf-8"))
    nonce = base64.b64decode(payload["nonce"])
    ct = base64.b64decode(payload["ciphertext"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")
