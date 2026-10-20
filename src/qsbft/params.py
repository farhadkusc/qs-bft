"""Table 2 of the preprint, plus the constants fixed by the experimental section."""

from __future__ import annotations

# Mersenne prime 2^31-1. Table 2 marks M as implementation-specific.
MODULUS = 2_147_483_647
# δ = 1/2 + d with d = 1/3.
DELTA = 0.5 + (1.0 / 3.0)
# QKD material width used in the experimental setup.
QKD_KEY_BITS = 256
BLOCK_BYTES = 1024
TX_BYTES = 256
TXS_PER_RUN = 1000
RUNS = 10
NODE_SIZES = (4, 5, 6, 7, 8, 9, 10)
# Timeouts satisfy T1 < T2 - T. Units are abstract ticks.
T = 3
T1 = 5
T2 = 9


def faults(n: int) -> int:
    """f = floor((N-1)/3), the Table 2 formula. N = 3f+1 is exact at 4, 7, and 10."""
    if n < 4:
        raise ValueError("N must be at least 4")
    return (n - 1) // 3


def quorum(n: int) -> int:
    return 2 * faults(n) + 1


def verifiers(n: int) -> int:
    """K = N - 1. The remaining node is the signer."""
    return n - 1
