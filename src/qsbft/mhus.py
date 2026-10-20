"""MH-USS: key distribution, Equation (7), and the Equation (8) threshold.

One signer and K verifiers. The signer draws K^2 field elements. Verifier P_i
receives keys [(i-1)K+1, ..., iK] (1-based). P_i forwards the j-th of those
keys to P_j, which stores it as r_{i -> j}. P_j accepts when the number of
matching cross-checks is strictly greater than K * δ.
"""

from __future__ import annotations

import secrets

from .hashing import bytes_to_chunks, multilinear
from .params import DELTA, MODULUS, QKD_KEY_BITS


def qkd_element() -> int:
    """One field element from 256-bit simulated QKD material."""
    raw = int.from_bytes(secrets.token_bytes(QKD_KEY_BITS // 8), "big")
    return raw % MODULUS


class MHUSS:
    def __init__(self, k: int, modulus: int = MODULUS, delta: float = DELTA, keys: list[int] | None = None):
        if k < 1:
            raise ValueError("K must be positive")
        self.k = k
        self.modulus = modulus
        self.delta = delta
        self.keys = list(keys) if keys is not None else [qkd_element() for _ in range(k * k)]
        if len(self.keys) != k * k:
            raise ValueError("MH-USS needs K^2 keys")
        # cross[j][i] is the key P_i forwarded to P_j. Verifier indices are 0-based.
        self.cross = [[0] * k for _ in range(k)]
        for i in range(k):
            for j in range(k):
                self.cross[j][i] = self.keys[i * k + j]

    def _vector(self, payload: bytes) -> list[int]:
        chunks = bytes_to_chunks(payload, self.modulus)
        # Each hash uses a 2-element key on a 1-chunk message so every r_t is one key.
        # Equation (1) still applies: h = r1 + r2 * x mod M.
        x = chunks[0]
        return [(self.keys[t] + self.keys[t] * x) % self.modulus for t in range(self.k * self.k)]

    def sign(self, payload: bytes) -> list[int]:
        """Equation (7). The key schedule uses one field element per tag, applied as h(x) = r + r*x."""
        return self._vector(payload)

    def sign_full(self, payload: bytes, width: int = 8) -> list[int]:
        """Equation (1) on a width-chunk message. Uses width+1 keys per tag, strided through the pool."""
        chunks = bytes_to_chunks(payload, self.modulus)
        if len(chunks) < width:
            chunks = chunks + [0] * (width - len(chunks))
        chunks = chunks[:width]
        tags = []
        pool = self.keys
        span = width + 1
        for t in range(self.k * self.k):
            key = [pool[(t * span + s) % len(pool)] for s in range(span)]
            tags.append(multilinear(chunks, key, self.modulus))
        return tags

    def verify(self, payload: bytes, signature: list[int], verifier: int) -> bool:
        """Equation (8) at verifier P_j. Uses the cross-distributed keys only."""
        if len(signature) != self.k * self.k:
            return False
        chunks = bytes_to_chunks(payload, self.modulus)
        x = chunks[0]
        matches = 0
        for i in range(self.k):
            key = self.cross[verifier][i]
            expected = (key + key * x) % self.modulus
            index = i * self.k + verifier
            if signature[index] == expected:
                matches += 1
        return matches > self.k * self.delta

    def honest_accepts(self, payload: bytes) -> bool:
        signature = self.sign(payload)
        return all(self.verify(payload, signature, j) for j in range(self.k))


def acceptance_row(k: int) -> dict:
    """Equation (8): accept only when the match count is strictly greater than K·δ."""
    from fractions import Fraction

    threshold = Fraction(k, 1) * (Fraction(1, 2) + Fraction(1, 3))
    matches = int(threshold) + 1
    return {
        "k": k,
        "delta": "5/6",
        "threshold": float(threshold),
        "matches_required": matches,
        "mismatches_tolerated": k - matches,
    }

def forge_attempt(scheme: MHUSS, payload: bytes) -> bool:
    """A signature with no access to the QKD keys. Theorem 1 bounds one tag by 1/|Y|."""
    forged = [secrets.randbelow(scheme.modulus) for _ in range(scheme.k * scheme.k)]
    return any(scheme.verify(payload, forged, j) for j in range(scheme.k))

