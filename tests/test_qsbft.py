import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from qsbft.experiment import COEFFICIENTS, blocks_of, build_transactions, payment_records
from qsbft.hashing import avalanche, multilinear, parametric_hash, toeplitz, universality
from qsbft.mhus import MHUSS, acceptance_row, forge_attempt
from qsbft.params import BLOCK_BYTES, DELTA, MODULUS, NODE_SIZES, T, T1, T2, TXS_PER_RUN, TX_BYTES, faults
from qsbft.protocol import (
    fast_messages,
    pbft_normal_messages,
    pbft_view_change_messages,
    quorum_intersection,
    run_round,
    standard_messages,
)


class PreprintTests(unittest.TestCase):
    def test_equation_1(self):
        self.assertEqual(multilinear([2, 3], [5, 7, 11], modulus=101), (5 + 7 * 2 + 11 * 3) % 101)

    def test_timeout_order(self):
        self.assertLess(T1, T2 - T)

    def test_delta(self):
        self.assertAlmostEqual(DELTA, 0.5 + 1.0 / 3.0)

    def test_faults_follow_the_floor_formula(self):
        self.assertEqual([faults(n) for n in NODE_SIZES], [1, 1, 1, 2, 2, 2, 3])
        self.assertEqual([n for n in NODE_SIZES if n == 3 * faults(n) + 1], [4, 7, 10])

    def test_honest_signature_accepted_and_forgery_rejected(self):
        scheme = MHUSS(3)
        payload = b"consumer-payment"
        self.assertTrue(scheme.honest_accepts(payload))
        self.assertEqual(acceptance_row(3)["matches_required"], 3)
        self.assertEqual(acceptance_row(3)["mismatches_tolerated"], 0)
        for _ in range(20):
            self.assertFalse(forge_attempt(scheme, payload))

    def test_threshold_rejects_a_short_match(self):
        scheme = MHUSS(3)
        payload = b"consumer-payment"
        signature = scheme.sign(payload)
        signature[0] = (signature[0] + 1) % MODULUS
        self.assertFalse(scheme.verify(payload, signature, 0))

    def test_fast_mode_commits_one_block(self):
        result = run_round(4, 5, b"\x02" * 64, [2, 3, 5, 7])
        self.assertEqual(result.mode, "fast")
        self.assertEqual(result.primary, 5 % 4)
        self.assertEqual(len(set(result.locked)), 1)
        self.assertEqual(result.messages, 1 + 5 * 3)

    def test_standard_and_empty(self):
        standard = run_round(4, 0, b"\x02" * 64, [2, 3, 5, 7], invalid_preprepare=1)
        self.assertEqual(standard.mode, "standard")
        self.assertNotEqual(standard.committed, "empty")
        silent = run_round(7, 2, b"\x02" * 64, [2, 3, 5, 7], primary_silent=True)
        self.assertEqual(silent.mode, "empty-block")
        self.assertEqual(silent.committed, "empty")
        self.assertEqual(len(set(silent.locked)), 1)

    def test_message_counts_on_the_tested_grid(self):
        for n in NODE_SIZES:
            self.assertEqual(fast_messages(n), 1 + 5 * (n - 1))
            self.assertEqual(standard_messages(n), 1 + 7 * (n - 1))
        self.assertEqual(pbft_view_change_messages(10) / (2 * 10 * 10), 5)
        self.assertEqual(pbft_normal_messages(4), 3 + 2 * 4 * 3)
        self.assertEqual(run_round(5, 0, b"\x02" * 64, COEFFICIENTS).mode, "fast")

    def test_quorum_intersection_matches_theorem_4_when_n_is_3f_plus_1(self):
        for n in (4, 7, 10):
            row = quorum_intersection(n)
            self.assertTrue(row["n_equals_3f_plus_1"])
            self.assertTrue(row["bound_holds"])
            self.assertGreaterEqual(row["min_intersection"], row["f"] + 1)
        five = quorum_intersection(5)
        self.assertFalse(five["n_equals_3f_plus_1"])
        self.assertLess(five["min_intersection"], five["theorem4_bound_f_plus_1"])

    def test_parametric_hash_changes_with_one_bit(self):
        payload = b"block-body-" + b"\x11" * 64
        self.assertGreater(avalanche(payload, COEFFICIENTS), 0.0)
        self.assertNotEqual(
            parametric_hash(payload, COEFFICIENTS),
            parametric_hash(payload + b"\x01", COEFFICIENTS),
        )

    def test_toeplitz_matches_definition(self):
        self.assertEqual(toeplitz([1, 2], [3, 4, 5], modulus=97), 23 % 97)

    def test_universality_on_a_small_field(self):
        row = universality(11)
        self.assertTrue(row["condition1_balanced"])
        self.assertEqual(row["max_joint_preimage"], row["expected_joint_preimage"])

    def test_experiment_shapes(self):
        rows = payment_records(8, seed=1)
        self.assertTrue(all(len(row["payload"]) == TX_BYTES for row in rows))
        blocks = blocks_of(build_transactions(TXS_PER_RUN, seed=1))
        self.assertEqual(len(blocks), TXS_PER_RUN // (BLOCK_BYTES // TX_BYTES))
        self.assertTrue(all(len(block) == BLOCK_BYTES for block in blocks))


if __name__ == "__main__":
    unittest.main()
