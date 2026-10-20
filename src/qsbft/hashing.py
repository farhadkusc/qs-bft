"""Equation (1) and a cubic parametric hash in the shape of Definition 2."""

from __future__ import annotations

import hashlib

from .params import MODULUS


def multilinear(message: list[int], key: list[int], modulus: int = MODULUS) -> int:
    """h(x) = r_1 + sum_i r_{i+1} x_i  (mod M). key has length len(message)+1."""
    if len(key) != len(message) + 1:
        raise ValueError("multilinear key must have length n+1")
    acc = key[0]
    for coef, item in zip(key[1:], message):
        acc = (acc + coef * item) % modulus
    return acc


def toeplitz(message: list[int], key: list[int], modulus: int = MODULUS) -> int:
    """Naive Toeplitz product. key has length 2n-1, laid out as the first column then the first row."""
    n = len(message)
    if len(key) != 2 * n - 1:
        raise ValueError("Toeplitz key must have length 2n-1")
    acc = 0
    for i in range(n):
        for j in range(n):
            # Diagonal index: the generating vector is indexed by (i-j) + (n-1).
            acc = (acc + key[(i - j) + (n - 1)] * message[j]) % modulus
    return acc


def bytes_to_chunks(payload: bytes, modulus: int = MODULUS) -> list[int]:
    if not payload:
        return [0]
    out = []
    for i in range(0, len(payload), 4):
        out.append(int.from_bytes(payload[i : i + 4], "big") % modulus)
    return out


def parametric_hash(payload: bytes, coefficients: list[int], prime: int = MODULUS) -> int:
    """Cubic chain: sum_i a_i * x_i * x_{i+1} * x_{i+2} mod p.

    Definition 2 writes each component as a degree-three monomial. The chain
    above is that shape on a byte-chunk vector, with the coefficient vector
    cycling when the message is longer than the coefficient list. Equation (4)
    as printed does not define the a_i, so the coefficient list is an input.
    """
    chunks = bytes_to_chunks(payload, prime)
    if len(chunks) < 3:
        chunks = (chunks + [0, 0, 0])[:3]
    acc = 0
    m = len(coefficients)
    for i in range(len(chunks)):
        a = coefficients[i % m]
        x0 = chunks[i]
        x1 = chunks[(i + 1) % len(chunks)]
        x2 = chunks[(i + 2) % len(chunks)]
        acc = (acc + a * x0 * x1 * x2) % prime
    return acc


def avalanche(payload: bytes, coefficients: list[int]) -> float:
    """Fraction of output bits that flip when input bit 0 flips. Output is 31 bits of the prime field."""
    base = parametric_hash(payload, coefficients)
    flipped = bytearray(payload)
    flipped[0] ^= 0x01
    other = parametric_hash(bytes(flipped), coefficients)
    width = MODULUS.bit_length()
    xor = base ^ other
    return bin(xor).count("1") / width


def avalanche_survey(payload: bytes, coefficients: list[int], bit_limit: int = 256) -> dict:
    """Mean fraction of the 31 output bits that flip, over one-bit input changes."""
    width = MODULUS.bit_length()
    flips = []
    total_bits = min(bit_limit, len(payload) * 8)
    base = parametric_hash(payload, coefficients)
    for bit in range(total_bits):
        mutated = bytearray(payload)
        mutated[bit // 8] ^= 1 << (bit % 8)
        other = parametric_hash(bytes(mutated), coefficients)
        flips.append(bin(base ^ other).count("1") / width)
    return {
        "bits_flipped": total_bits,
        "output_bits": width,
        "mean": sum(flips) / len(flips),
        "minimum": min(flips),
        "maximum": max(flips),
    }


def universality(modulus: int = 17) -> dict:
    """Conditions (2) and (3) of Definition 1, for one-chunk messages."""
    expected = modulus  # |H| / |Y| = M
    condition1 = True
    for x in range(modulus):
        bucket = [0] * modulus
        for r1 in range(modulus):
            for r2 in range(modulus):
                bucket[(r1 + r2 * x) % modulus] += 1
        if any(count != expected for count in bucket):
            condition1 = False
            break
    max_joint = 0
    for x1 in range(modulus):
        for x2 in range(modulus):
            if x1 == x2:
                continue
            joint = [0] * (modulus * modulus)
            for r1 in range(modulus):
                for r2 in range(modulus):
                    y1 = (r1 + r2 * x1) % modulus
                    y2 = (r1 + r2 * x2) % modulus
                    joint[y1 * modulus + y2] += 1
            max_joint = max(max_joint, max(joint))
    return {
        "modulus": modulus,
        "message_chunks": 1,
        "condition1_balanced": condition1,
        "expected_preimage": expected,
        "max_joint_preimage": max_joint,
        "expected_joint_preimage": 1,
    }


def sha256_bytes(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()
