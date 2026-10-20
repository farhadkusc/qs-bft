"""Algorithm 1 of the preprint.

Primary for round r is L = r mod N. A round is fast when at least 3f+1 votes
support h(p). It is standard when that quorum is missed: either at least 2f+1
votes arrived, or the fast-mode window closed. Feedback is sent after at least
f+1 resolution votes. f is floor((N-1)/3) from Table 2.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from .hashing import parametric_hash
from .params import T, T1, T2, faults


@dataclass
class RoundResult:
    n: int
    f: int
    round_index: int
    primary: int
    mode: str
    committed: str
    messages: int
    locked: list[str] = field(default_factory=list)


def primary_index(round_index: int, n: int) -> int:
    return round_index % n


def _tally(votes: list[str], target: str) -> int:
    return sum(1 for vote in votes if vote == target)


def run_round(
    n: int,
    round_index: int,
    block: bytes,
    coefficients: list[int],
    *,
    primary_silent: bool = False,
    invalid_preprepare: int = 0,
) -> RoundResult:
    """One execution of Algorithm 1.

    invalid_preprepare is how many secondaries reject PRE-PREPARE and vote empty.
    The primary's proposal counts as its own vote for h(p). primary_silent skips
    every primary broadcast; secondaries then exchange empty votes, which is the
    liveness case in Theorem 5.
    """
    f = faults(n)
    primary = primary_index(round_index, n)
    secondaries = [i for i in range(n) if i != primary]
    digest = format(parametric_hash(block, coefficients), "x")
    fast_need = 3 * f + 1
    commit_need = 2 * f + 1
    feedback_need = f + 1

    if primary_silent:
        # Each secondary sends an empty vote to every other secondary.
        messages = len(secondaries) * (len(secondaries) - 1)
        committed = "empty" if len(secondaries) >= commit_need else "none"
        return RoundResult(
            n, f, round_index, primary, "empty-block", committed, messages, ["empty"] * n
        )

    messages = 1  # client REQUEST
    messages += n - 1  # PRE-PREPARE
    votes = []
    for offset, _node in enumerate(secondaries):
        votes.append("empty" if offset < invalid_preprepare else digest)
    messages += n - 1  # VOTE to L

    block_votes = _tally(votes, digest)
    votes_for_block = block_votes + 1

    if votes_for_block >= fast_need and _within_fast_timeout():
        messages += n - 1  # FAST-RESOLVE
        messages += n - 1  # resolution votes
        messages += n - 1  # FEEDBACK
        return RoundResult(n, f, round_index, primary, "fast", digest, messages, [digest] * n)

    # Algorithm 1 enters standard mode on a partial quorum or when T expires.
    messages += n - 1  # PRE-COMMIT
    messages += n - 1  # votes
    messages += n - 1  # PRE-RESOLVE
    messages += n - 1  # votes
    if votes_for_block >= commit_need and block_votes >= feedback_need:
        messages += n - 1  # FEEDBACK
        committed = digest
        locked = [digest] * n
    else:
        messages += len(secondaries) * max(len(secondaries) - 1, 0)
        committed = "empty"
        locked = ["empty"] * n
    return RoundResult(n, f, round_index, primary, "standard", committed, messages, locked)


def _within_fast_timeout() -> bool:
    return T1 < T2 - T


def fast_messages(n: int) -> int:
    result = run_round(n, 0, b"\x01" * 64, [3, 5, 7, 9])
    if result.mode != "fast":
        raise RuntimeError(f"unanimous round was {result.mode} at N={n}")
    return result.messages


def standard_messages(n: int) -> int:
    """A standard-mode commit: one short of the fast quorum, still at least 2f+1."""
    f = faults(n)
    invalid = n - 3 * f
    result = run_round(n, 0, b"\x01" * 64, [3, 5, 7, 9], invalid_preprepare=invalid)
    if result.mode != "standard" or result.committed == "empty":
        raise RuntimeError(f"standard round did not commit at N={n}: {result}")
    return result.messages


def pbft_normal_messages(n: int) -> int:
    """PRE-PREPARE plus all-to-all PREPARE and COMMIT."""
    return (n - 1) + 2 * n * (n - 1)


def pbft_view_change_messages(n: int) -> int:
    """Table 4's faulty PBFT term evaluated as N^3.

    N^3 / (2 N^2) = N/2, which is the factor of 5 the preprint states at N=10.
    """
    return n ** 3


def quorum_intersection(n: int) -> dict:
    """Minimum overlap of two commit quorums of size 2f+1. Theorem 4 uses N = 3f+1."""
    f = faults(n)
    width = 2 * f + 1
    groups = list(itertools.combinations(range(n), width))
    smallest = n
    below = 0
    pairs = 0
    for left, right in itertools.combinations(groups, 2):
        pairs += 1
        overlap = len(set(left) & set(right))
        smallest = min(smallest, overlap)
        if overlap < f + 1:
            below += 1
    exact = n == 3 * f + 1
    return {
        "n": n,
        "f": f,
        "quorum": width,
        "quorum_sets": len(groups),
        "pairs": pairs,
        "min_intersection": smallest,
        "theorem4_bound_f_plus_1": f + 1,
        "pairs_below_f_plus_1": below,
        "n_equals_3f_plus_1": exact,
        "bound_holds": smallest >= f + 1,
    }
