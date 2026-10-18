"""Deterministic Unit Tests for Phase 03F R16.8.1 Single-Trial Runner.

Verifies:
1. Candidate version metadata and strategy alignment (R16.8.1, observation_complete_v6).
2. All three conditions (BASELINE, CONVENTIONAL, PROVENANCE_AWARE) produce distinct canonical summary and trace paths.
3. Global pairwise uniqueness across all 14 configurations and 2 models.
4. Model identifier sanitization works accurately (e.g. qwen2.5:7b-instruct -> qwen2_5_7b).
5. Overwrite protection safeguards:
   - Summary overwrite refusal when target file exists.
   - Traces overwrite refusal when target directory exists and is non-empty.
   - Traces overwrite refusal when target directory exists and is empty.
   - Fresh distinct canonical paths pass validation.
6. Sequential condition isolation: completed BASELINE run does not block CONVENTIONAL or PROVENANCE_AWARE.
7. Cross-condition mismatch detection (e.g. BASELINE run with CONVENTIONAL summary path).
8. Path containment, root escape, and path traversal ('..') rejection.
9. Invalid input rejection (unregistered config_id, invalid condition, invalid model_name).
10. Strict protection of historical R16.2–R16.8 artifacts:
    - Reserved exact files (including R16.8 summaries).
    - Reserved directory prefixes (including traces/phase_03f_r16_8).
    - Ensures R16.8.1 paths are not falsely blocked by R16.8 prefix.
11. Host RAM safety thresholds remain calibrated (7.0 GiB preflight, 5.0 GiB emergency stop, 3.0 GiB floor).
12. Single-trial execution gate: execution_authorized=False raises SingleTrialExecutionNotAuthorizedError without file writes.
13. Coordinator configuration: CancelablePipelineCoordinator wires R16.8.1 pipeline version and observation_complete_v6 strategy.
14. CLI parser arguments and default validation-only mode contract.
"""

import os
import sys
import json
import shutil
import tempfile
import threading
import unittest

# Ensure project root is available in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.run_phase_03f_single_trial_r16_8_1 import (
    ALL_CONFIGS,
    CONFIGS_BY_ID,
    VALID_CONDITIONS,
    VALID_MODELS,
    DEFAULT_MODEL,
    PIPELINE_VERSION,
    RESEARCHER_STRATEGY,
    ALLOWED_SUMMARY_PATH,
    ALLOWED_TRACES_DIR,
    RAM_PREFLIGHT_THRESHOLD_GB,
    RAM_EMERGENCY_STOP_THRESHOLD_GB,
    RAM_MIN_THRESHOLD_GB,
    RESERVED_EXACT_FILES,
    RESERVED_DIRECTORY_PREFIXES,
    SingleTrialExecutionNotAuthorizedError,
    CancelablePipelineCoordinator,
    sanitize_model_identifier,
    get_canonical_output_paths,
    validate_output_paths,
    validate_single_trial_runner,
    evaluate_ram_headroom,
    run_single_trial,
    build_parser,
    resolve_normalized_path,
    PROJECT_ROOT,
)


class TestR1681RunnerMetadataAndContract(unittest.TestCase):
    """Test candidate metadata, versioning, and CLI parser contract for R16.8.1."""

    def test_candidate_version_metadata(self):
        """Runner declares PIPELINE_VERSION R16.8.1 and strategy observation_complete_v6."""
        self.assertEqual(PIPELINE_VERSION, "R16.8.1")
        self.assertEqual(RESEARCHER_STRATEGY, "observation_complete_v6")
        self.assertEqual(ALLOWED_SUMMARY_PATH, "reports/phase_03f_r16_8_1_single_trial_summary.json")
        self.assertEqual(ALLOWED_TRACES_DIR, "traces/phase_03f_r16_8_1")

    def test_cli_parser_contract(self):
        """CLI parser includes required flags, defaults, and choices."""
        parser = build_parser()
        # Default parse
        args = parser.parse_args([])
        self.assertFalse(args.execute_single_trial)
        self.assertFalse(args.validate_only)
        self.assertIsNone(args.config_id)
        self.assertIsNone(args.condition)
        self.assertIsNone(args.summary_path)
        self.assertIsNone(args.traces_dir)
        self.assertEqual(args.model_name, DEFAULT_MODEL)

        # Explicit parse
        custom_args = parser.parse_args([
            "--config-id", "BK-DSC-05",
            "--condition", "CONVENTIONAL",
            "--model-name", "qwen2.5:7b-instruct",
            "--execute-single-trial",
            "--summary-path", "reports/custom.json",
            "--traces-dir", "traces/custom",
        ])
        self.assertEqual(custom_args.config_id, "BK-DSC-05")
        self.assertEqual(custom_args.condition, "CONVENTIONAL")
        self.assertEqual(custom_args.model_name, "qwen2.5:7b-instruct")
        self.assertTrue(custom_args.execute_single_trial)
        self.assertEqual(custom_args.summary_path, "reports/custom.json")
        self.assertEqual(custom_args.traces_dir, "traces/custom")


class TestR1681ConditionIsolatedPaths(unittest.TestCase):
    """Test condition-isolated canonical output paths and safeguards in R16.8.1."""

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
        self.assertEqual(os.path.basename(b_sum), "phase_03f_r16_8_1_BK-DSC-05_BASELINE_qwen2_5_7b_summary.json")
        self.assertEqual(os.path.basename(b_trc), "phase_03f_r16_8_1_BK-DSC-05_BASELINE_qwen2_5_7b")
        self.assertEqual(os.path.basename(c_sum), "phase_03f_r16_8_1_BK-DSC-05_CONVENTIONAL_qwen2_5_7b_summary.json")
        self.assertEqual(os.path.basename(c_trc), "phase_03f_r16_8_1_BK-DSC-05_CONVENTIONAL_qwen2_5_7b")
        self.assertEqual(os.path.basename(p_sum), "phase_03f_r16_8_1_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b_summary.json")
        self.assertEqual(os.path.basename(p_trc), "phase_03f_r16_8_1_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b")

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
        """Runner strictly refuses dispatch when target summary file already exists."""
        sum_path, trc_path = get_canonical_output_paths("BK-DSC-05", "CONVENTIONAL", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)
        os.makedirs(os.path.dirname(sum_path), exist_ok=True)
        with open(sum_path, "w", encoding="utf-8") as f:
            f.write('{"status": "MOCK_RUN"}')

        res = validate_output_paths(sum_path, trc_path, base_dir=self.tmp_dir)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("already exists" in err.lower() and "refusing to overwrite" in err.lower() for err in res.errors))

    def test_overwrite_protection_refusal_when_traces_non_empty(self):
        """Runner strictly refuses dispatch when target traces directory exists and is non-empty."""
        sum_path, trc_path = get_canonical_output_paths("BK-DSC-05", "CONVENTIONAL", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)
        os.makedirs(trc_path, exist_ok=True)
        with open(os.path.join(trc_path, "trial-test.json"), "w", encoding="utf-8") as f:
            f.write('{"run_id": "test"}')

        res = validate_output_paths(sum_path, trc_path, base_dir=self.tmp_dir)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("non-empty" in err.lower() and "refusing to overwrite" in err.lower() for err in res.errors))

    def test_overwrite_protection_refusal_when_traces_empty(self):
        """Runner strictly refuses dispatch when target traces directory already exists, even if empty."""
        sum_path, trc_path = get_canonical_output_paths("BK-DSC-05", "CONVENTIONAL", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)
        os.makedirs(trc_path, exist_ok=True)
        self.assertEqual(len(os.listdir(trc_path)), 0, "Traces directory must be empty for this test.")

        res = validate_output_paths(sum_path, trc_path, base_dir=self.tmp_dir)
        self.assertFalse(res.is_valid)
        self.assertTrue(any("empty" in err.lower() and "already exists" in err.lower() for err in res.errors))

        # Also verify via validate_single_trial_runner
        report = validate_single_trial_runner(
            config_id="BK-DSC-05",
            condition="CONVENTIONAL",
            model_name="qwen2.5:7b-instruct",
            base_dir=self.tmp_dir,
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("empty" in err.lower() for err in report["errors"]))

    def test_fresh_distinct_canonical_paths_pass_validation(self):
        """Fresh, distinct canonical paths for BASELINE, CONVENTIONAL, and PROVENANCE_AWARE pass validation."""
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
        """Attempting to output a CONVENTIONAL run to a BASELINE summary path is caught and rejected."""
        b_sum, _ = get_canonical_output_paths("BK-DSC-05", "BASELINE", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)
        _, c_trc = get_canonical_output_paths("BK-DSC-05", "CONVENTIONAL", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)

        res = validate_output_paths(
            summary_path=b_sum,
            traces_dir=c_trc,
            base_dir=self.tmp_dir,
            expected_condition="CONVENTIONAL",
        )
        self.assertFalse(res.is_valid)
        self.assertTrue(any("condition mismatch" in err.lower() for err in res.errors))

    def test_path_traversal_and_containment_rejected(self):
        """Path traversal sequences ('..') and root escapes are strictly rejected."""
        res_escape = validate_output_paths(
            summary_path="../escaped.json",
            traces_dir="traces/phase_03f_r16_8_1",
            base_dir=self.tmp_dir,
        )
        self.assertFalse(res_escape.is_valid)
        self.assertTrue(any("traversal" in err.lower() or "escapes" in err.lower() for err in res_escape.errors))

        res_trc_traversal = validate_output_paths(
            summary_path="reports/valid.json",
            traces_dir="traces/../escaped_traces",
            base_dir=self.tmp_dir,
        )
        self.assertFalse(res_trc_traversal.is_valid)
        self.assertTrue(any("traversal" in err.lower() for err in res_trc_traversal.errors))

        # Non-JSON summary
        res_non_json = validate_output_paths(
            summary_path="reports/summary.txt",
            traces_dir="traces/valid_dir",
            base_dir=self.tmp_dir,
        )
        self.assertFalse(res_non_json.is_valid)
        self.assertTrue(any("must be a .json file" in err.lower() for err in res_non_json.errors))

        # Identical summary and traces
        res_identical = validate_output_paths(
            summary_path="reports/same.json",
            traces_dir="reports/same.json",
            base_dir=self.tmp_dir,
        )
        self.assertFalse(res_identical.is_valid)
        self.assertTrue(any("identical" in err.lower() for err in res_identical.errors))

    def test_invalid_config_condition_model_rejected(self):
        """Invalid configurations, conditions, and models are rejected by derivation and validation."""
        with self.assertRaises(ValueError):
            get_canonical_output_paths("NON_EXISTENT_CFG", "CONVENTIONAL", "qwen2.5:7b-instruct")

        with self.assertRaises(ValueError):
            get_canonical_output_paths("BK-DSC-05", "UNSUPPORTED_COND", "qwen2.5:7b-instruct")

        with self.assertRaises(ValueError):
            get_canonical_output_paths("BK-DSC-05", "CONVENTIONAL", "unsupported:model")

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
        """Historical summaries from R16.2–R16.8 and reserved directories remain strictly protected."""
        r16_8_summaries = [
            "reports/phase_03f_r16_8_single_trial_summary.json",
            "reports/phase_03f_r16_8_BK-DSC-05_BASELINE_qwen2_5_7b_summary.json",
            "reports/phase_03f_r16_8_BK-DSC-05_CONVENTIONAL_qwen2_5_7b_summary.json",
            "reports/phase_03f_r16_8_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b_summary.json",
        ]
        for sum_file in r16_8_summaries:
            self.assertIn(sum_file, RESERVED_EXACT_FILES, f"Missing historical file: {sum_file}")
            res = validate_output_paths(
                summary_path=sum_file,
                traces_dir="traces/phase_03f_r16_8_1_test",
                base_dir=PROJECT_ROOT,
            )
            self.assertFalse(res.is_valid)
            self.assertTrue(any("collides with reserved project artifact" in e.lower() for e in res.errors))

        # Check historical trace directories collision
        r16_historical_dirs = [
            "traces/phase_03f_r16_8_BK-DSC-05_BASELINE_qwen2_5_7b",
            "traces/phase_03f_r16_7_BK-DSC-05_BASELINE_qwen2_5_7b",
            "traces/phase_03f_r16_6_BK-DSC-05_BASELINE_qwen2_5_7b",
            "traces/phase_03f_r16_5_BK-DSC-05_BASELINE_qwen2_5_7b",
        ]
        for trc_dir in r16_historical_dirs:
            res_trc = validate_output_paths(
                summary_path="reports/phase_03f_r16_8_1_test.json",
                traces_dir=trc_dir,
                base_dir=PROJECT_ROOT,
            )
            self.assertFalse(res_trc.is_valid)
            self.assertTrue(any("reserved historical" in e.lower() for e in res_trc.errors))

        # Verify that fresh R16.8.1 paths are NOT rejected as colliding with traces/phase_03f_r16_8
        valid_r16_8_1_traces = os.path.join(self.tmp_dir, "traces", "phase_03f_r16_8_1_BK-DSC-05_CONVENTIONAL_qwen2_5_7b")
        valid_r16_8_1_summary = os.path.join(self.tmp_dir, "reports", "phase_03f_r16_8_1_BK-DSC-05_CONVENTIONAL_qwen2_5_7b_summary.json")
        res_r16_8_1 = validate_output_paths(
            summary_path=valid_r16_8_1_summary,
            traces_dir=valid_r16_8_1_traces,
            base_dir=self.tmp_dir,
            expected_config_id="BK-DSC-05",
            expected_condition="CONVENTIONAL",
            expected_model_name="qwen2.5:7b-instruct",
        )
        self.assertTrue(res_r16_8_1.is_valid, f"Fresh R16.8.1 path must be valid, got: {res_r16_8_1.errors}")

    def test_ram_thresholds_unmodified(self):
        """Host RAM safety thresholds remain calibrated and unchanged in R16.8.1."""
        self.assertEqual(RAM_PREFLIGHT_THRESHOLD_GB, 7.0)
        self.assertEqual(RAM_EMERGENCY_STOP_THRESHOLD_GB, 5.0)
        self.assertEqual(RAM_MIN_THRESHOLD_GB, 3.0)

        # Binary arithmetic verification (1024 ** 3)
        pass_res, gb_val = evaluate_ram_headroom(int(7.0 * (1024 ** 3)), threshold_gb=7.0)
        self.assertTrue(pass_res)
        self.assertAlmostEqual(gb_val, 7.0, places=4)

        fail_res, gb_fail = evaluate_ram_headroom(int(6.9 * (1024 ** 3)), threshold_gb=7.0)
        self.assertFalse(fail_res)
        self.assertAlmostEqual(gb_fail, 6.9, places=4)

    def test_execution_authorization_gate_raises_without_side_effects(self):
        """run_single_trial without execution_authorized=True raises SingleTrialExecutionNotAuthorizedError without file writes."""
        sum_path, trc_path = get_canonical_output_paths("BK-DSC-05", "CONVENTIONAL", "qwen2.5:7b-instruct", base_dir=self.tmp_dir)

        with self.assertRaises(SingleTrialExecutionNotAuthorizedError):
            run_single_trial(
                config_id="BK-DSC-05",
                condition="CONVENTIONAL",
                execution_authorized=False,
                summary_path=sum_path,
                traces_dir=trc_path,
                base_dir=self.tmp_dir,
                model_name="qwen2.5:7b-instruct",
            )

        # Zero persistent files created
        self.assertFalse(os.path.exists(sum_path))
        self.assertFalse(os.path.exists(trc_path))

    def test_coordinator_integration_and_version_wiring(self):
        """CancelablePipelineCoordinator wires PIPELINE_VERSION R16.8.1 and RESEARCHER_STRATEGY observation_complete_v6."""
        cancellation_event = threading.Event()
        coordinator = CancelablePipelineCoordinator(
            cancellation_event=cancellation_event,
            model_name="qwen2.5:3b",
            traces_dir=os.path.join(self.tmp_dir, "traces"),
        )
        self.assertEqual(coordinator.pipeline_version, "R16.8.1")
        self.assertEqual(coordinator.researcher_strategy, "observation_complete_v6")
        self.assertEqual(coordinator.planner.pipeline_version, "R16.8.1")
        self.assertEqual(coordinator.researcher.strategy, "observation_complete_v6")

        # Verify planner prompt guidelines include R16.8.1 transaction guidelines
        guidelines = coordinator.planner._get_update_scheduled_transaction_guidelines()
        self.assertIn("Evidence of the existing scheduled transaction is REQUIRED", guidelines)
        self.assertIn("OMIT the optional `recipient` parameter", guidelines)
        self.assertIn("NEVER pass a new recipient", guidelines)

    def test_non_executing_validation_defaults_to_canonical_paths(self):
        """Runner non-executing validation defaults to condition-isolated canonical paths."""
        report = validate_single_trial_runner(
            config_id="BK-DSC-05",
            condition="CONVENTIONAL",
            model_name="qwen2.5:7b-instruct",
            base_dir=self.tmp_dir,
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["config_id"], "BK-DSC-05")
        self.assertEqual(report["condition"], "CONVENTIONAL")
        self.assertEqual(report["model_name"], "qwen2.5:7b-instruct")

        expected_sum_suffix = os.path.normpath("reports/phase_03f_r16_8_1_BK-DSC-05_CONVENTIONAL_qwen2_5_7b_summary.json")
        expected_trc_suffix = os.path.normpath("traces/phase_03f_r16_8_1_BK-DSC-05_CONVENTIONAL_qwen2_5_7b")
        self.assertTrue(report["output_summary_path"].endswith(expected_sum_suffix))
        self.assertTrue(report["output_traces_dir"].endswith(expected_trc_suffix))


if __name__ == "__main__":
    unittest.main()
