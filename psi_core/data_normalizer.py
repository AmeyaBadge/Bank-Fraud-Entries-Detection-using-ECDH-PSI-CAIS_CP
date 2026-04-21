"""
psi_core/data_normalizer.py
Identifier normalization — ensures format differences don't break cryptographic matching.
"""

import re


def normalize(raw_string: str, identifier_type: str) -> str:
    """
    Normalize a raw identifier string according to its type.

    'email'          → lowercase, strip leading/trailing whitespace
    'phone'          → strip all non-numeric characters, remove leading country code (91)
    'account_number' → strip all non-alphanumeric characters, uppercase
    'aadhaar'        → strip all non-numeric characters (12 digits only)

    Raises ValueError if identifier_type is not recognized.
    """
    if not raw_string:
        raise ValueError("Identifier cannot be empty")

    raw = raw_string.strip()

    if identifier_type == "email":
        return raw.lower()

    elif identifier_type == "phone":
        digits = re.sub(r'\D', '', raw)
        # Remove leading +91 or 0091 or 91 (Indian country code)
        if digits.startswith("0091"):
            digits = digits[4:]
        elif digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        elif digits.startswith("0") and len(digits) == 11:
            digits = digits[1:]
        return digits

    elif identifier_type == "account_number":
        cleaned = re.sub(r'[^A-Za-z0-9]', '', raw)
        return cleaned.upper()

    elif identifier_type == "aadhaar":
        digits = re.sub(r'\D', '', raw)
        # Aadhaar is always 12 digits
        if len(digits) != 12:
            raise ValueError(f"Aadhaar must be 12 digits, got {len(digits)}")
        return digits

    else:
        raise ValueError(f"Unknown identifier_type: '{identifier_type}'")
