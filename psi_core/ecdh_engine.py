"""
psi_core/ecdh_engine.py
ECDH-PSI Querier and Responder logic over NIST P-256 (secp256r1).
"""

import os
import base64
import hashlib
from concurrent.futures import ProcessPoolExecutor
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, EllipticCurvePublicKey, generate_private_key
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.backends import default_backend

# We operate directly on EC integers via the cryptography library's internal
# primitives. For ECDH-PSI we need raw scalar multiplication, so we use
# cryptography's EllipticCurvePrivateKey as a wrapper around the scalar.

# ---------------------------------------------------------------------------
# Low-level helpers: We represent EC points as (x, y) integer tuples and
# perform arithmetic using the curve parameters directly for maximum control.
# We use the cryptography library for point serialization/deserialization.
# ---------------------------------------------------------------------------

# NIST P-256 curve parameters
P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _mod_inv(a: int, m: int) -> int:
    """Extended Euclidean algorithm for modular inverse."""
    if a == 0:
        raise ZeroDivisionError("modular inverse of 0")
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % m


def _point_add(P1, P2):
    """Add two EC points in affine coordinates."""
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2:
        if y1 != y2:
            return None  # point at infinity
        # Point doubling
        lam = (3 * x1 * x1 + A) * _mod_inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _mod_inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mult(k: int, point) -> tuple:
    """Double-and-add scalar multiplication."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _point_on_curve(x: int, y: int) -> bool:
    """Verify a point (x, y) lies on P-256."""
    lhs = (y * y) % P
    rhs = (x * x * x + A * x + B) % P
    return lhs == rhs


# ─── Hash-to-Curve (try-and-increment) ────────────────────────────────────────

def _hash_to_curve(identifier: str) -> tuple:
    """
    Deterministically maps a normalized identifier string to a P-256 point.
    Uses try-and-increment (RFC 9380 compatible style):
    - Hash the identifier + counter using SHA-256
    - Interpret digest as x-coordinate
    - Try to solve y² = x³ + ax + b mod P
    - Increment counter until a valid x is found
    """
    counter = 0
    while True:
        data = f"{identifier}:{counter}".encode("utf-8")
        digest = hashlib.sha256(data).digest()
        x = int.from_bytes(digest, "big") % P
        rhs = (pow(x, 3, P) + A * x + B) % P
        # Compute square root via Tonelli-Shanks; P-256 allows shortcut p≡3(mod4)
        # P-256: P mod 4 == 3, so sqrt = rhs^((P+1)//4) mod P
        y = pow(rhs, (P + 1) // 4, P)
        if (y * y) % P == rhs:
            return (x, y)
        counter += 1


# ─── Point Serialization ──────────────────────────────────────────────────────

def _serialize_point(point: tuple) -> bytes:
    """Serialize an EC point to compressed 33-byte format, then base64-encode."""
    x, y = point
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    serialized = prefix + x.to_bytes(32, "big")
    return base64.b64encode(serialized)


def _deserialize_point(data: bytes) -> tuple:
    """
    Deserialize a base64-encoded compressed P-256 point.
    Validates the point lies on P-256 before returning.
    Raises ValueError on invalid data.
    """
    raw = base64.b64decode(data)
    if len(raw) != 33 or raw[0] not in (0x02, 0x03):
        raise ValueError("Invalid compressed EC point format")
    x = int.from_bytes(raw[1:], "big")
    if x >= P:
        raise ValueError("EC point x-coordinate out of range")
    rhs = (pow(x, 3, P) + A * x + B) % P
    y = pow(rhs, (P + 1) // 4, P)
    if (y * y) % P != rhs:
        raise ValueError("EC point not on P-256 curve")
    # Select correct y parity
    if raw[0] == 0x02:
        if y % 2 != 0:
            y = P - y
    else:
        if y % 2 != 1:
            y = P - y
    return (x, y)


# ─── Worker helpers for ProcessPoolExecutor ───────────────────────────────────

def _encrypt_single(args):
    identifier, scalar = args
    pt = _hash_to_curve(identifier)
    encrypted = _scalar_mult(scalar, pt)
    return _serialize_point(encrypted)


def _double_encrypt_single(args):
    point_b64, scalar = args
    pt = _deserialize_point(point_b64)
    encrypted = _scalar_mult(scalar, pt)
    return _serialize_point(encrypted)


# ─── PSIQuerier ───────────────────────────────────────────────────────────────

class PSIQuerier:
    """
    Used by Bank A (the querier) to perform the ECDH-PSI protocol.
    Generates a fresh ephemeral private scalar per instance (per PSI session).
    The scalar is never stored, logged, or transmitted.
    """

    def __init__(self):
        # Generate a fresh random 256-bit ephemeral private scalar
        self._scalar = int.from_bytes(os.urandom(32), "big") % N
        while self._scalar == 0:
            self._scalar = int.from_bytes(os.urandom(32), "big") % N

    def hash_to_curve(self, identifier: str) -> tuple:
        return _hash_to_curve(identifier)

    def encrypt_set(self, identifiers: list) -> list:
        """
        Apply hash_to_curve + scalar multiplication (by private scalar a) to each identifier.
        Returns list of base64-encoded compressed EC points.
        Uses ProcessPoolExecutor for parallelism when set > 500 items.
        """
        args = [(ident, self._scalar) for ident in identifiers]
        if len(identifiers) > 500:
            with ProcessPoolExecutor() as executor:
                results = list(executor.map(_encrypt_single, args))
        else:
            results = [_encrypt_single(a) for a in args]
        return results

    def double_encrypt_remote(self, remote_points: list) -> list:
        """
        Takes Bank B's P(Y)*b serialized points and multiplies by scalar a.
        Produces (P(Y)*b)*a for intersection comparison.
        """
        args = [(pt, self._scalar) for pt in remote_points]
        if len(remote_points) > 500:
            with ProcessPoolExecutor() as executor:
                results = list(executor.map(_double_encrypt_single, args))
        else:
            results = [_double_encrypt_single(a) for a in args]
        return results

    def find_intersection(
        self,
        double_enc_own: list,
        double_enc_remote: list,
        originals: list
    ) -> list:
        """
        Computes set intersection between:
          - double_enc_own:    (P(X)*a)*b  — Bank A's set, double-encrypted
          - double_enc_remote: (P(Y)*b)*a  — Bank B's blacklist, double-encrypted
        Returns the original plaintext identifiers for matched EC points.
        """
        remote_set = set(
            pt.decode("utf-8") if isinstance(pt, bytes) else pt
            for pt in double_enc_remote
        )
        matched = []
        for enc, original in zip(double_enc_own, originals):
            key = enc.decode("utf-8") if isinstance(enc, bytes) else enc
            if key in remote_set:
                matched.append(original)
        return matched


# ─── PSIResponder ─────────────────────────────────────────────────────────────

class PSIResponder:
    """
    Used by Bank B (the responder) to process PSI exchange requests.
    Generates a fresh ephemeral private scalar per instance (per PSI session).
    """

    def __init__(self):
        self._scalar = int.from_bytes(os.urandom(32), "big") % N
        while self._scalar == 0:
            self._scalar = int.from_bytes(os.urandom(32), "big") % N

    def process_query(self, querier_points: list) -> list:
        """
        Takes Bank A's P(X)*a points, multiplies by scalar b.
        Returns (P(X)*a)*b.
        """
        args = [(pt, self._scalar) for pt in querier_points]
        if len(querier_points) > 500:
            with ProcessPoolExecutor() as executor:
                results = list(executor.map(_double_encrypt_single, args))
        else:
            results = [_double_encrypt_single(a) for a in args]
        return results

    def encrypt_blacklist(self, identifiers: list) -> list:
        """
        Encrypts Bank B's own blacklist identifiers with scalar b.
        Returns P(Y)*b for each entry.
        """
        args = [(ident, self._scalar) for ident in identifiers]
        if len(identifiers) > 500:
            with ProcessPoolExecutor() as executor:
                results = list(executor.map(_encrypt_single, args))
        else:
            results = [_encrypt_single(a) for a in args]
        return results
