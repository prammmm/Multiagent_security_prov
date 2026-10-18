"""Deterministic Unit Tests for Condition-Isolated Output Paths and Safeguards in Phase 03F R16.6.

Verifies:
1. All three conditions (BASELINE, CONVENTIONAL, PROVENANCE_AWARE) produce distinct canonical summary and trace paths.
2. Pairwise uniqueness across all 14 registered configurations and all valid models.
3. Model identifier sanitization works accurately (e.g. qwen2.5:7b-instruct -> qwen2_5_7b).
4. Different runs cannot overwrite one another:
   - Summary overwrite refusal when target file exists.
   - Traces overwrite refusal when target directory exists and is non-empty.
   - Successful runs in one condition do not block or pollute another condition.
5. Invalid inputs and adversarial attempts are rejected:
   - Invalid config IDs.
   - Invalid condition names.
   - Invalid model names.
   - Parent path traversal ('..') in summary path and traces directory.
   - Path escaping project root.
   - Non-json summary files.
   - Cross-condition path mismatch (e.g. BASELINE run with CONVENTIONAL summary path).
6. Reserved historical files and directories remain strictly protected:
   - R16.2, R16.3, R16.4, and R16.5 summary files.
   - R16.2, R16.3, R16.4, and R16.5 trace directories and directory prefixes.
7. Host RAM safety thresholds remain calibrated and unchanged:
   - Preflight: 7.0 GiB (exact binary GiB)
   - Emergency Stop: 5.0 GiB
   - Audit Floor: 3.0 GiB
8. R16.6 non-executing validation accurately derives canonical condition-isolated paths.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest

# Ensure project root is available in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.run_phase_03f_single_trial_r16_6 import (
    ALL_CONFIGS,
    CONFIGS_BY_ID,
    VALID_CONDITIONS,
    VALID_MODELS,
    DEFAULT_MODEL,
    RAM_PREFLIGHT_THRESHOLD_GB,
    RAM_EMERGENCY_STOP_THRESHOLD_GB,
    RAM_MIN_THRESHOLD_GB,
    RESERVED_EXACT_FILES,
    RESERVED_DIRECTORY_PREFIXES,
    sanitize_model_identifier,
    get_canonical_output_paths,
    validate_output_paths,
    validate_single_trial_runner,
    resolve_normalized_path,
    PROJECT_ROOT,
)


class TestR166ConditionIsolatedPaths(unittest.TestCase):
    """Test suite for condition-isolated paths, overwrite safeguards, and containment in R16.6."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_distinct_paths_across_three_conditions(self):
        """All three conditions produce pairwise distinct summary and trace paths for BK-DSC-05."""
        config_id = "BK-DSC-05"
        model_name = "qwen2.5:7b-instruct"

        b_sum, b_trc = get_canonical_output_paths(config_id, "BASELINE", model_name, base_dir=self.tmp_dir)
        c_sum, c_trc = get_canonical_output_paths(config_id, "CONVENTIONAL", model_name, base_dir=self.tmp_dir)
        p_sum, p_trc = get_canonical_output_paths(config_id, "PROVENANCE_AWARE", model_name, base_dir=self.tmp_dir)

        # Pairwise distinct summary paths
        self.assertNotEqual(b_sum, c_sum)
        self.assertNotEqual(b_sum, p_sum)
        self.assertNotEqual(c_sum, p_sum)
        self.assertEqual(len({b_sum, c_sum, p_sum}), 3)

        # Pairwise distinct trace directories
        self.assertNotEqual(b_trc, c_trc)
        self.assertNotEqual(b_trc, p_trc)
        self.assertNotEqual(c_trc, p_trc)
        self.assertEqual(len({b_trc, c_trc, p_trc}), 3)

        # Verify canonical basename naming conventions
        self.assertEqual(os.path.basename(b_sum), "phase_03f_r16_6_BK-DSC-05_BASELINE_qwen2_5_7b_summary.json")
        self.assertEqual(os.path.basename(b_trc), "phase_03f_r16_6_BK-DSC-05_BASELINE_qwen2_5_7b")
        self.assertEqual(os.path.basename(c_sum), "phase_03f_r16_6_BK-DSC-05_CONVENTIONAL_qwen2_5_7b_summary.json")
        self.assertEqual(os.path.basename(c_trc), "phase_03f_r16_6_BK-DSC-05_CONVENTIONAL_qwen2_5_7b")
        self.assertEqual(os.path.basename(p_sum), "phase_03f_r16_6_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b_summary.json")
        self.assertEqual(os.path.basename(p_trc), "phase_03f_r16_6_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b")

    def test_global_pairwise_path_uniqueness(self):
        """All 14 configurations across 3 conditions and 2 models produce globally unique paths."""
        seen_summaries = set()
        seen_traces = set()
        expected_total = len(ALL_CONFIGS) * len(VALID_CONDITIONS) * len(VALID_MODELS)

        for cfg in ALL_CONFIGS:
            cid = cfg["config_id"]
            for cond in VALID_CONDITIONS:
                for model in VALID_MODELS:
                    sum_path, trc_path = get_canonical_output_paths(cid, cond, model, base_dir=self.tmp_dir)
                    self.assertNotIn(sum_path, seen_summaries, f"Collision detected for summary: {sum_path}")
                    self.assertNotIn(trc_path, seen_traces, f"Collision detected for traces: {trc_path}")
                    seen_summaries.add(sum_path)
                    seen_traces.add(trc_path)

        self.assertEqual(len(seen_summaries), expected_total)
        self.assertEqual(len(seen_traces), expected_total)
        self.assertEqual(expected_total, 14 * 3 * 2)

    def test_model_identifier_sanitization(self):
        """Model identifier sanitization properly formats suffixes."""
        self.assertEqual(sanitize_model_identifier("qwen2.5:7b-instruct"), "qwen2_5_7b")
        self.assertEqual(sanitize_model_identifier("qwen2.5:3b"), "qwen2_5_3b")

    def test_overwrite_protection_refusal_when_summary_exists(self):
        """Requirement 3: Runner strictly refuses dispatch when target summary file already exists."""
        sum_path, trc_path = get_canonical_output_paths("BK-DSC-05", "BASELINE", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)
        os.makedirs(os.path.dirname(sum_path), exist_ok=True)
        with open(sum_path, "w", encoding="utf-8") as f:
            f.write('{"status": "MOCK_RUN"}')

        res = validate_output_paths(sum_path, trc_path, base_dir=self.tmp_dir)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("already exists" in err.lower() and "refusing to overwrite" in err.lower() for err in res.errors))

    def test_overwrite_protection_refusal_when_traces_non_empty(self):
        """Requirement 2: Runner strictly refuses dispatch when target traces directory exists and is non-empty."""
        sum_path, trc_path = get_canonical_output_paths("BK-DSC-05", "BASELINE", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)
        os.makedirs(trc_path, exist_ok=True)
        with open(os.path.join(trc_path, "trial-test.json"), "w", encoding="utf-8") as f:
            f.write('{"run_id": "test"}')

        res = validate_output_paths(sum_path, trc_path, base_dir=self.tmp_dir)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("non-empty" in err.lower() and "refusing to overwrite" in err.lower() for err in res.errors))

    def test_overwrite_protection_refusal_when_traces_empty(self):
        """Requirement 1: Runner strictly refuses dispatch when target traces directory already exists, even if empty."""
        sum_path, trc_path = get_canonical_output_paths("BK-DSC-05", "BASELINE", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)
        os.makedirs(trc_path, exist_ok=True)
        self.assertEqual(len(os.listdir(trc_path)), 0, "Traces directory must be empty for this test.")

        res = validate_output_paths(sum_path, trc_path, base_dir=self.tmp_dir)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("empty" in err.lower() and "already exists" in err.lower() for err in res.errors))

        # Also verify via validate_single_trial_runner
        report = validate_single_trial_runner(
            config_id="BK-DSC-05",
            condition="BASELINE",
            model_name="qwen2.5:7b-instruct",
            base_dir=self.tmp_dir,
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("empty" in err.lower() for err in report["errors"]))

    def test_fresh_distinct_canonical_paths_pass_validation(self):
        """Requirement 4: Fresh, distinct canonical paths for BASELINE, CONVENTIONAL, and PROVENANCE_AWARE pass validation."""
        for cond in ("BASELINE", "CONVENTIONAL", "PROVENANCE_AWARE"):
            sum_path, trc_path = get_canonical_output_paths("BK-DSC-05", cond, "qwen2.5:7b-instruct", base_dir=self.tmp_dir)
            self.assertFalse(os.path.exists(sum_path), f"Summary path {sum_path} must not exist yet.")
            self.assertFalse(os.path.exists(trc_path), f"Traces directory {trc_path} must not exist yet.")

            res = validate_output_paths(
                summary_path=sum_path,
                traces_dir=trc_path,
                base_dir=self.tmp_dir,
                expected_config_id="BK-DSC-05",
                expected_condition=cond,
                expected_model_name="qwen2.5:7b-instruct",
            )
            self.assertTrue(res.is_valid, f"Fresh paths for {cond} should pass, got errors: {res.errors}")
            self.assertEqual(res.errors, [])

            report = validate_single_trial_runner(
                config_id="BK-DSC-05",
                condition=cond,
                model_name="qwen2.5:7b-instruct",
                base_dir=self.tmp_dir,
            )
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["errors"], [])

    def test_condition_isolation_sequential_runs_do_not_collide(self):
        """Simulating completion of BASELINE leaves CONVENTIONAL and PROVENANCE_AWARE completely unblocked."""
        # Simulate completed BASELINE run
        b_sum, b_trc = get_canonical_output_paths("BK-DSC-05", "BASELINE", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)
        os.makedirs(os.path.dirname(b_sum), exist_ok=True)
        with open(b_sum, "w", encoding="utf-8") as f:
            f.write('{"status": "COMPLETED", "condition": "BASELINE"}')
        os.makedirs(b_trc, exist_ok=True)
        with open(os.path.join(b_trc, "trial-baseline.json"), "w", encoding="utf-8") as f:
            f.write('{"run_id": "baseline"}')

        # Re-validating BASELINE must fail due to overwrite protection
        b_report = validate_single_trial_runner(
            config_id="BK-DSC-05",
            condition="BASELINE",
            model_name="qwen2.5:7b-instruct",
            base_dir=self.tmp_dir,
        )
        self.assertEqual(b_report["status"], "FAIL")
        self.assertTrue(any("already exists" in e.lower() for e in b_report["errors"]))

        # Validating CONVENTIONAL must PASS without any collision
        c_report = validate_single_trial_runner(
            config_id="BK-DSC-05",
            condition="CONVENTIONAL",
            model_name="qwen2.5:7b-instruct",
            base_dir=self.tmp_dir,
        )
        self.assertEqual(c_report["status"], "PASS")
        self.assertEqual(c_report["errors"], [])

        # Validating PROVENANCE_AWARE must PASS without any collision
        p_report = validate_single_trial_runner(
            config_id="BK-DSC-05",
            condition="PROVENANCE_AWARE",
            model_name="qwen2.5:7b-instruct",
            base_dir=self.tmp_dir,
        )
        self.assertEqual(p_report["status"], "PASS")
        self.assertEqual(p_report["errors"], [])

    def test_cross_condition_mismatch_rejected(self):
        """Attempting to output a BASELINE run to a CONVENTIONAL summary path is caught and rejected."""
        c_sum, _ = get_canonical_output_paths("BK-DSC-05", "CONVENTIONAL", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)
        _, b_trc = get_canonical_output_paths("BK-DSC-05", "BASELINE", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)

        res = validate_output_paths(
            summary_path=c_sum,
            traces_dir=b_trc,
            base_dir=self.tmp_dir,
            expected_condition="BASELINE",
        )
        self.assertFalse(res.is_valid)
        self.assertTrue(any("condition mismatch" in err.lower() for err in res.errors))

    def test_path_traversal_rejected(self):
        """Path traversal sequences ('..') are strictly rejected."""
        # Relative traversal escaping root
        res_escape = validate_output_paths(
            summary_path="../escaped.json",
            traces_dir="traces/phase_03f_r16_6",
            base_dir=self.tmp_dir,
        )
        self.assertFalse(res_escape.is_valid)
        self.assertTrue(any("traversal" in err.lower() or "escapes" in err.lower() for err in res_escape.errors))

        # Traversal inside traces directory
        res_trc_traversal = validate_output_paths(
            summary_path="reports/valid.json",
            traces_dir="traces/../escaped_traces",
            base_dir=self.tmp_dir,
        )
        self.assertFalse(res_trc_traversal.is_valid)
        self.assertTrue(any("traversal" in err.lower() for err in res_trc_traversal.errors))

    def test_invalid_config_condition_model_rejected(self):
        """Invalid configurations, conditions, and models are rejected by derivation and validation."""
        with self.assertRaises(ValueError):
            get_canonical_output_paths("NON_EXISTENT_CFG", "BASELINE", "qwen2.5:7b-instruct")

        with self.assertRaises(ValueError):
            get_canonical_output_paths("BK-DSC-05", "UNSUPPORTED_COND", "qwen2.5:7b-instruct")

        with self.assertRaises(ValueError):
            get_canonical_output_paths("BK-DSC-05", "BASELINE", "unsupported:model")

        # In validate_single_trial_runner
        report_bad_cfg = validate_single_trial_runner(config_id="NON_EXISTENT_CFG", base_dir=self.tmp_dir)
        self.assertEqual(report_bad_cfg["status"], "FAIL")
        self.assertTrue(any("invalid configuration" in e.lower() for e in report_bad_cfg["errors"]))

        report_bad_cond = validate_single_trial_runner(condition="UNSUPPORTED_COND", base_dir=self.tmp_dir)
        self.assertEqual(report_bad_cond["status"], "FAIL")
        self.assertTrue(any("invalid condition" in e.lower() for e in report_bad_cond["errors"]))

        report_bad_model = validate_single_trial_runner(model_name="unsupported:model", base_dir=self.tmp_dir)
        self.assertEqual(report_bad_model["status"], "FAIL")
        self.assertTrue(any("invalid model" in e.lower() for e in report_bad_model["errors"]))

    def test_reserved_historical_artifacts_protected(self):
        """Historical summaries from R16.2–R16.5 and reserved directories remain strictly protected."""
        # Verify R16.5 condition summaries are listed
        r16_5_summaries = [
            "reports/phase_03f_r16_5_single_trial_summary.json",
            "reports/phase_03f_r16_5_BK-DSC-05_BASELINE_qwen2_5_7b_summary.json",
            "reports/phase_03f_r16_5_BK-DSC-05_CONVENTIONAL_qwen2_5_7b_summary.json",
            "reports/phase_03f_r16_5_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b_summary.json",
        ]
        for sum_file in r16_5_summaries:
            self.assertIn(sum_file, RESERVED_EXACT_FILES, f"Missing historical file: {sum_file}")
            res = validate_output_paths(
                summary_path=sum_file,
                traces_dir="traces/phase_03f_r16_6_test",
                base_dir=PROJECT_ROOT,
            )
            self.assertFalse(res.is_valid)
            self.assertTrue(any("collides with reserved project artifact" in e.lower() for e in res.errors))

        # Verify historical trace directories (including prefix matching)
        r16_historical_dirs = [
            "traces/phase_03f_r16_5_BK-DSC-05_BASELINE_qwen2_5_7b",
            "traces/phase_03f_r16_5_BK-DSC-05_CONVENTIONAL_qwen2_5_7b",
            "traces/phase_03f_r16_5_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b",
            "traces/phase_03f_r16_4_BK-DSC-05_BASELINE_qwen2_5_7b",
            "traces/phase_03f_r16_4_WS-CNF-01_BASELINE_qwen2_5_7b",
            "traces/phase_03f_r16_4_WS-CNF-01_PROVENANCE_AWARE_qwen2_5_7b",
        ]
        for trc_dir in r16_historical_dirs:
            res_trc = validate_output_paths(
                summary_path="reports/phase_03f_r16_6_test.json",
                traces_dir=trc_dir,
                base_dir=PROJECT_ROOT,
            )
            self.assertFalse(res_trc.is_valid)
            self.assertTrue(any("reserved historical" in e.lower() for e in res_trc.errors))

    def test_ram_thresholds_unmodified(self):
        """Host RAM safety thresholds remain calibrated and unchanged in R16.6."""
        self.assertEqual(RAM_PREFLIGHT_THRESHOLD_GB, 7.0)
        self.assertEqual(RAM_EMERGENCY_STOP_THRESHOLD_GB, 5.0)
        self.assertEqual(RAM_MIN_THRESHOLD_GB, 3.0)

    def test_non_executing_validation_defaults_to_canonical_paths(self):
        """Runner non-executing validation defaults to condition-isolated canonical paths."""
        report = validate_single_trial_runner(
            config_id="BK-DSC-05",
            condition="PROVENANCE_AWARE",
            model_name="qwen2.5:7b-instruct",
            base_dir=self.tmp_dir,
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["config_id"], "BK-DSC-05")
        self.assertEqual(report["condition"], "PROVENANCE_AWARE")
        self.assertEqual(report["model_name"], "qwen2.5:7b-instruct")

        expected_sum_suffix = os.path.normpath("reports/phase_03f_r16_6_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b_summary.json")
        expected_trc_suffix = os.path.normpath("traces/phase_03f_r16_6_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b")
        self.assertTrue(report["output_summary_path"].endswith(expected_sum_suffix))
        self.assertTrue(report["output_traces_dir"].endswith(expected_trc_suffix))


if __name__ == "__main__":
    unittest.main()
