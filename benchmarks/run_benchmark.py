#!/usr/bin/env python3
"""Write the measured tables for the preprint experiment."""

from __future__ import annotations

import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from qsbft import __version__
from qsbft.experiment import (
    COEFFICIENTS,
    complexity_table,
    consensus_trace,
    safety_table,
    summarize,
    threshold_table,
    time_protocol,
    write_blocks,
    write_transactions,
)
from qsbft.hashing import avalanche_survey, multilinear, toeplitz, universality
from qsbft.params import BLOCK_BYTES, MODULUS, NODE_SIZES, RUNS, TXS_PER_RUN, TX_BYTES


def write_key_schedule(path: Path) -> None:
    import random

    from qsbft.mhus import MHUSS

    rng = random.Random(20260310)
    keys = [rng.randrange(MODULUS) for _ in range(9)]
    scheme = MHUSS(3, keys=keys)
    message = b"consumer-payment"
    signature = scheme.sign(message)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "k": 3,
                "modulus": MODULUS,
                "seed": 20260310,
                "note": "Seeded field elements for a readable schedule. Timed runs draw 256-bit keys with secrets and reduce modulo M.",
                "keys_r": keys,
                "cross_r_i_to_j": scheme.cross,
                "message_utf8": message.decode(),
                "signature": signature,
                "accepted_by_each_verifier": [scheme.verify(message, signature, j) for j in range(3)],
            },
            indent=2,
        )
        + "\n"
    )


def hash_race(repeats: int = 2000, widths: tuple[int, ...] = (4, 8, 16, 32)) -> list[dict]:
    rows = []
    for width in widths:
        message = list(range(1, width + 1))
        linear_key = list(range(width + 1))
        toeplitz_key = list(range(2 * width - 1))
        start = time.perf_counter()
        for _ in range(repeats):
            multilinear(message, linear_key, modulus=MODULUS)
        linear_s = time.perf_counter() - start
        start = time.perf_counter()
        for _ in range(repeats):
            toeplitz(message, toeplitz_key, modulus=MODULUS)
        toeplitz_s = time.perf_counter() - start
        rows.append(
            {
                "width": width,
                "repeats": repeats,
                "multilinear_multiplications": width,
                "toeplitz_multiplications": width * width,
                "multiplication_ratio": width,
                "multilinear_s": linear_s,
                "toeplitz_s": toeplitz_s,
                "toeplitz_over_multilinear": toeplitz_s / linear_s,
            }
        )
    return rows


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _svg(path: Path, title: str, ylabel: str, series: list[tuple[str, str, list[tuple[float, float, float]]]]) -> None:
    width, height = 760, 440
    left, right, top, bottom = 84, 36, 46, 58
    plot_w = width - left - right
    plot_h = height - top - bottom
    ys = [y for _, _, points in series for _, y, _ in points]
    y_max = max(ys) * 1.15 if ys else 1.0
    xs = [x for _, _, points in series for x, _, _ in points]
    x_min, x_max = min(xs), max(xs)

    def px(x: float) -> float:
        return left + (x - x_min) / (x_max - x_min) * plot_w

    def py(y: float) -> float:
        return top + (1 - y / y_max) * plot_h

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#f7f5f0"/>',
        f'<text x="{left}" y="28" font-family="Georgia, serif" font-size="18" fill="#1c1915">{title}</text>',
    ]
    for tick in range(5):
        value = y_max * tick / 4
        y = py(value)
        if y_max >= 100:
            label = f"{value:,.0f}"
        elif y_max >= 10:
            label = f"{value:.1f}"
        else:
            label = f"{value:.2f}"
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="#ddd6c8"/>')
        parts.append(
            f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" font-family="ui-sans-serif, sans-serif" font-size="11" fill="#5c564c">{label}</text>'
        )
    for x in sorted(set(xs)):
        parts.append(
            f'<text x="{px(x):.1f}" y="{height - 28}" text-anchor="middle" font-family="ui-sans-serif, sans-serif" font-size="12" fill="#1c1915">{int(x)}</text>'
        )
    parts.append(
        f'<text x="{width / 2:.0f}" y="{height - 8}" text-anchor="middle" font-family="ui-sans-serif, sans-serif" font-size="12" fill="#5c564c">Nodes N</text>'
    )
    parts.append(
        f'<text x="18" y="{height / 2:.0f}" text-anchor="middle" transform="rotate(-90 18 {height / 2:.0f})" font-family="ui-sans-serif, sans-serif" font-size="12" fill="#5c564c">{ylabel}</text>'
    )
    legend_x = left
    for name, color, points in series:
        coords = " ".join(f"{px(x):.1f},{py(y):.1f}" for x, y, _ in points)
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2.4" points="{coords}"/>')
        for x, y, sd in points:
            parts.append(f'<line x1="{px(x):.1f}" y1="{py(y - sd):.1f}" x2="{px(x):.1f}" y2="{py(max(y + sd, 0)):.1f}" stroke="{color}" stroke-width="1.2"/>')
            parts.append(f'<circle cx="{px(x):.1f}" cy="{py(y):.1f}" r="3.2" fill="{color}"/>')
        parts.append(
            f'<rect x="{legend_x}" y="{height - 52}" width="10" height="10" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{legend_x + 14}" y="{height - 43}" font-family="ui-sans-serif, sans-serif" font-size="11" fill="#1c1915">{name}</text>'
        )
        legend_x += 180
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n")


def main() -> None:
    out = ROOT / "benchmarks" / "results"
    out.mkdir(parents=True, exist_ok=True)
    data = ROOT / "data"
    write_transactions(data / "transactions.csv")
    write_blocks(data / "blocks.bin")
    write_key_schedule(data / "mhus_key_schedule_k3.json")
    trace = consensus_trace(4, seed=1)
    _write_csv(data / "consensus_trace_n4.csv", trace)

    raw = []
    for n in NODE_SIZES:
        for kind in ("qs-bft-fast", "qs-bft-standard", "pbft"):
            for seed in range(RUNS):
                raw.append(time_protocol(n, seed, kind))
                last = raw[-1]
                print(
                    kind,
                    "N",
                    n,
                    "seed",
                    seed,
                    "tps",
                    round(last["throughput_tps"], 1),
                    "ms",
                    round(last["block_latency_ms"], 4),
                    flush=True,
                )
    summary = []
    for n in NODE_SIZES:
        for kind in ("qs-bft-fast", "qs-bft-standard", "pbft"):
            rows = [row for row in raw if row["n"] == n and row["protocol"] == kind]
            item = summarize(rows)
            summary.append(item)
    block = (data / "blocks.bin").read_bytes()[:BLOCK_BYTES]
    report = {
        "package": "qs-bft",
        "version": __version__,
        "preprint_doi": "10.21203/rs.3.rs-9084418/v1",
        "preprint_url": "https://doi.org/10.21203/rs.3.rs-9084418/v1",
        "language": "Python 3",
        "preprint_testbed": "Go 1.21, goroutines, loopback TCP, Intel i7-11700, 16 GB, Ubuntu 22.04",
        "modulus": MODULUS,
        "delta": "1/2 + 1/3",
        "coefficients": COEFFICIENTS,
        "transactions": TXS_PER_RUN,
        "transaction_bytes": TX_BYTES,
        "block_bytes": BLOCK_BYTES,
        "runs": RUNS,
        "node_sizes": list(NODE_SIZES),
        "complexity": complexity_table(),
        "thresholds": threshold_table(),
        "safety": safety_table(),
        "hash_race": hash_race(),
        "avalanche": avalanche_survey(block, COEFFICIENTS, bit_limit=256),
        "universality_m17": universality(17),
        "summary": summary,
        "trace_n4_rounds": len(trace),
        "trace_n4_fast_rounds": sum(1 for row in trace if row["mode"] == "fast"),
        "trace_n4_empty_rounds": sum(1 for row in trace if row["mode"] == "empty-block"),
        "runs_raw": raw,
    }
    (out / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n")
    _write_csv(out / "summary.csv", summary)
    _write_csv(out / "complexity.csv", report["complexity"])
    _write_csv(out / "safety.csv", report["safety"])
    _write_csv(out / "thresholds.csv", report["thresholds"])
    _write_csv(out / "hash_race.csv", report["hash_race"])
    _write_csv(out / "runs.csv", raw)

    def points(kind: str, field: str, sd_field: str):
        return [
            (row["n"], row[field], row[sd_field])
            for row in summary
            if row["protocol"] == kind
        ]

    figures = ROOT / "docs" / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    _svg(
        figures / "throughput.svg",
        "Measured throughput, mean ± 1 SD",
        "Transactions / s",
        [
            ("QS-BFT fast", "#9a3412", points("qs-bft-fast", "throughput_mean", "throughput_sd")),
            ("QS-BFT standard", "#b45309", points("qs-bft-standard", "throughput_mean", "throughput_sd")),
            ("PBFT", "#1e3a5f", points("pbft", "throughput_mean", "throughput_sd")),
        ],
    )
    _svg(
        figures / "latency.svg",
        "Measured block latency, mean ± 1 SD",
        "Milliseconds / block",
        [
            ("QS-BFT fast", "#9a3412", points("qs-bft-fast", "block_latency_mean_ms", "block_latency_sd_ms")),
            ("QS-BFT standard", "#b45309", points("qs-bft-standard", "block_latency_mean_ms", "block_latency_sd_ms")),
            ("PBFT", "#1e3a5f", points("pbft", "block_latency_mean_ms", "block_latency_sd_ms")),
        ],
    )
    print("wrote", out / "evaluation.json")


if __name__ == "__main__":
    main()
