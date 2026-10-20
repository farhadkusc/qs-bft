"""The preprint's experiment: N from 4 to 10, 1000 transactions, 10 runs.

Block size is 1024 bytes and each transaction is 256 bytes, so a round
carries four transactions. Both consensus paths authenticate with MH-USS.
QKD keys are drawn before each timed run. The timer covers signature
generation and verification only, one signature per Algorithm 1 or PBFT
message, checked by each receiver of that message.
"""

from __future__ import annotations

import hashlib
import statistics
import time
from pathlib import Path

from .mhus import MHUSS, acceptance_row
from .params import BLOCK_BYTES, NODE_SIZES, RUNS, TXS_PER_RUN, TX_BYTES, faults
from .protocol import (
    fast_messages,
    pbft_normal_messages,
    pbft_view_change_messages,
    quorum_intersection,
    run_round,
    standard_messages,
)

# Public coefficient vector for the cubic parametric hash. Definition 2's
# printed formula for a_i does not determine these values.
COEFFICIENTS = [3, 5, 7, 11, 13, 17, 19, 23]


def payment_records(n_tx: int = TXS_PER_RUN, seed: int = 0) -> list[dict]:
    """Deterministic 256-byte consumer payments. Not a packet capture."""
    rows = []
    for i in range(n_tx):
        payer = f"payer-{i % 50}"
        payee = f"payee-{(i * 3) % 50}"
        amount = (i * 17) % 100_000
        memo = f"memo-{i}"
        body = f"pay|{seed}|{i}|{payer}|{payee}|{amount}|{memo}".encode()
        digest = hashlib.sha256(body).digest()
        payload = (body + digest).ljust(TX_BYTES, b"\x00")[:TX_BYTES]
        rows.append(
            {
                "tx_id": i,
                "seed": seed,
                "payer": payer,
                "payee": payee,
                "amount_cents": amount,
                "memo": memo,
                "sha256": digest.hex(),
                "payload": payload,
            }
        )
    return rows


def build_transactions(n_tx: int = TXS_PER_RUN, seed: int = 0) -> list[bytes]:
    return [row["payload"] for row in payment_records(n_tx, seed)]


def blocks_of(transactions: list[bytes]) -> list[bytes]:
    width = BLOCK_BYTES // TX_BYTES
    blocks = []
    for i in range(0, len(transactions), width):
        chunk = b"".join(transactions[i : i + width])
        if len(chunk) < BLOCK_BYTES:
            chunk = chunk.ljust(BLOCK_BYTES, b"\x00")
        blocks.append(chunk[:BLOCK_BYTES])
    return blocks


def _phases(n: int, kind: str) -> list[tuple[int, int]]:
    """(signers, verifiers per signature) for one block."""
    if kind == "qs-bft-fast":
        return [
            (1, 1),
            (1, n - 1),
            (n - 1, 1),
            (1, n - 1),
            (n - 1, 1),
            (1, n - 1),
        ]
    if kind == "qs-bft-standard":
        return [
            (1, 1),
            (1, n - 1),
            (n - 1, 1),
            (1, n - 1),
            (n - 1, 1),
            (1, n - 1),
            (n - 1, 1),
            (1, n - 1),
        ]
    if kind == "pbft":
        return [
            (1, n - 1),
            (n, n - 1),
            (n, n - 1),
        ]
    raise ValueError(kind)


def _authenticate_round(scheme: MHUSS, digest: bytes, phases: list[tuple[int, int]]) -> int:
    ops = 0
    counter = 0
    for signers, verifiers in phases:
        for _ in range(signers):
            payload = digest + counter.to_bytes(2, "big")
            counter += 1
            signature = scheme.sign(payload)
            ops += 1
            for verifier in range(verifiers):
                if not scheme.verify(payload, signature, verifier % scheme.k):
                    raise RuntimeError("honest MH-USS signature was rejected")
                ops += 1
    return ops


def time_protocol(n: int, seed: int, kind: str) -> dict:
    transactions = build_transactions(TXS_PER_RUN, seed)
    blocks = blocks_of(transactions)
    scheme = MHUSS(n - 1)
    phases = _phases(n, kind)
    start = time.perf_counter()
    crypto_ops = 0
    for block in blocks:
        digest = hashlib.sha256(block).digest()
        crypto_ops += _authenticate_round(scheme, digest, phases)
    elapsed = time.perf_counter() - start
    return {
        "protocol": kind,
        "n": n,
        "seed": seed,
        "transactions": TXS_PER_RUN,
        "blocks": len(blocks),
        "elapsed_s": elapsed,
        "throughput_tps": TXS_PER_RUN / elapsed if elapsed else 0.0,
        "block_latency_ms": (elapsed / len(blocks)) * 1000.0,
        "crypto_ops": crypto_ops,
    }


def summarize(rows: list[dict]) -> dict:
    tps = [row["throughput_tps"] for row in rows]
    lat = [row["block_latency_ms"] for row in rows]
    return {
        "n": rows[0]["n"],
        "protocol": rows[0]["protocol"],
        "runs": len(rows),
        "throughput_mean": statistics.fmean(tps),
        "throughput_sd": statistics.stdev(tps) if len(tps) > 1 else 0.0,
        "block_latency_mean_ms": statistics.fmean(lat),
        "block_latency_sd_ms": statistics.stdev(lat) if len(lat) > 1 else 0.0,
    }


def complexity_table() -> list[dict]:
    rows = []
    for n in NODE_SIZES:
        f = faults(n)
        fast = fast_messages(n)
        standard = standard_messages(n)
        pbft = pbft_normal_messages(n)
        view = pbft_view_change_messages(n)
        rows.append(
            {
                "n": n,
                "f": f,
                "k": n - 1,
                "n_equals_3f_plus_1": n == 3 * f + 1,
                "fast_quorum": 3 * f + 1,
                "commit_quorum": 2 * f + 1,
                "algorithm1_fast_messages": fast,
                "algorithm1_standard_messages": standard,
                "pbft_normal_messages": pbft,
                "pbft_view_change_messages": view,
                "table4_qs_nofault_n2": n * n,
                "table4_qs_faulty_2n2": 2 * n * n,
                "table4_qsyac_2n2": 2 * n * n,
                "qsyac_n_equals_4f_plus_1": (n - 1) % 4 == 0,
                "table4_pbft_nofault_2n2": 2 * n * n,
                "table4_pbft_faulty_n3": view,
                "table4_worst_case_factor": view / (2 * n * n),
                "algorithm1_pbft_over_fast": pbft / fast,
            }
        )
    return rows


def threshold_table() -> list[dict]:
    rows = []
    for n in NODE_SIZES:
        row = acceptance_row(n - 1)
        row["n"] = n
        row["f"] = faults(n)
        rows.append(row)
    return rows


def safety_table() -> list[dict]:
    return [quorum_intersection(n) for n in NODE_SIZES]


def consensus_trace(n: int = 4, seed: int = 1) -> list[dict]:
    """One fast-mode chain, plus round 3 with a silent primary."""
    blocks = blocks_of(build_transactions(TXS_PER_RUN, seed))
    rows = []
    for index, block in enumerate(blocks):
        silent = index == 3
        result = run_round(
            n,
            index,
            block,
            COEFFICIENTS,
            primary_silent=silent,
        )
        rows.append(
            {
                "round": index,
                "n": n,
                "primary": result.primary,
                "mode": result.mode,
                "committed_empty": result.committed == "empty",
                "messages": result.messages,
                "locked_values": len(set(result.locked)),
            }
        )
    return rows


def write_transactions(path: Path, n_tx: int = TXS_PER_RUN, seed: int = 1) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = payment_records(n_tx, seed)
    lines = ["tx_id,seed,bytes,payer,payee,amount_cents,memo,sha256"]
    payloads = []
    for row in rows:
        payloads.append(row["payload"])
        lines.append(
            f"{row['tx_id']},{row['seed']},{len(row['payload'])},{row['payer']},{row['payee']},{row['amount_cents']},{row['memo']},{row['sha256']}"
        )
    path.write_text("\n".join(lines) + "\n")
    path.with_suffix(".bin").write_bytes(b"".join(payloads))


def write_blocks(path: Path, seed: int = 1) -> None:
    from .hashing import parametric_hash

    blocks = blocks_of(build_transactions(TXS_PER_RUN, seed))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(blocks))
    lines = ["block_index,bytes,tx_from,tx_to,sha256,parametric_hash"]
    width = BLOCK_BYTES // TX_BYTES
    for index, block in enumerate(blocks):
        start = index * width
        digest = hashlib.sha256(block).hexdigest()
        lines.append(
            f"{index},{len(block)},{start},{start + width - 1},{digest},{parametric_hash(block, COEFFICIENTS)}"
        )
    path.with_suffix(".csv").write_text("\n".join(lines) + "\n")
