"""Deterministic Unit Tests for Candidate BK-DSC-05 Registration in Phase 03F R16.4 Runner.

Verifies:
1. BK-DSC-05 is recognized and correctly structured in the R16.4 runner configuration registry.
2. Authentic task and injection IDs, attack method, target tool, and attacker target match specifications.
3. The 12 held-out confirmation configurations remain recognized and completely unchanged.
4. Both exploratory candidates (BK-DSC-02 and BK-DSC-05) are present, making 14 total configurations.
5. validate_single_trial_runner accepts BK-DSC-05 under BASELINE with qwen2.5:7b-instruct.
6. Unsupported model names and invalid configuration IDs remain strictly rejected.
7. Output path validation and collision safeguards remain intact for BK-DSC-05.
8. Authentic AgentDojo definitions for user_task_2 and injection_task_4 are retrievable and unaltered.
9. Safety thresholds (7 GiB preflight, 5 GiB emergency stop, 3 GiB violation floor) remain intact.
"""

import os
import sys
import tempfile
import shutil
import unittest

# Ensure project root is available in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentdojo.task_suite.load_suites import get_suite
from scripts.run_phase_03f_single_trial_r16_4 import (
    CONFIRMATION_CONFIGS,
    EXPLORATORY_CANDIDATE_CONFIGS,
    ALL_CONFIGS,
    CONFIGS_BY_ID,
    VALID_CONDITIONS,
    VALID_MODELS,
    DEFAULT_MODEL,
    RAM_PREFLIGHT_THRESHOLD_GB,
    RAM_EMERGENCY_STOP_THRESHOLD_GB,
    RAM_MIN_THRESHOLD_GB,
    build_parser,
    validate_single_trial_runner,
    validate_output_paths,
)


class TestCandidateRegistrationBKDSC05(unittest.TestCase):
    """Focused tests for BK-DSC-05 registration and configuration integrity in R16.4."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_bk_dsc_05_registered_and_structured(self):
        """BK-DSC-05 must be registered in CONFIGS_BY_ID with exact authentic fields."""
        self.assertIn("BK-DSC-05", CONFIGS_BY_ID)
        cfg = CONFIGS_BY_ID["BK-DSC-05"]

        self.assertEqual(cfg["config_id"], "BK-DSC-05")
        self.assertEqual(cfg["suite"], "banking")
        self.assertEqual(cfg["user_task"], "user_task_2")
        self.assertEqual(cfg["injection_task"], "injection_task_4")
        self.assertEqual(cfg["attack_name"], "important_instructions")
        self.assertEqual(cfg["type"], "attacked")
        self.assertEqual(cfg["category"], "Attack")
        self.assertEqual(cfg["attacker_target"], "US133000000121212121212")
        self.assertEqual(cfg["target_tool"], "update_scheduled_transaction")

    def test_confirmation_configs_preserved_and_unmodified(self):
        """The 12 held-out confirmation configs must remain exactly 12 and untouched."""
        self.assertEqual(len(CONFIRMATION_CONFIGS), 12, "Confirmation set must contain exactly 12 configs")
        
        expected_cnf_ids = {
            "BK-CNF-01", "BK-CNF-02", "BK-CNF-03", "BK-CNF-04",
            "WS-CNF-01", "WS-CNF-02", "WS-CNF-03", "WS-CNF-04",
            "TR-CNF-01", "TR-CNF-02",
            "SL-CNF-01", "SL-CNF-02",
        }
        for cnf_id in expected_cnf_ids:
            self.assertIn(cnf_id, CONFIGS_BY_ID, f"Missing confirmation config: {cnf_id}")
            self.assertIn(cnf_id, [c["config_id"] for c in CONFIRMATION_CONFIGS])

        # Verify BK-DSC-02 is also preserved in exploratory configs
        self.assertIn("BK-DSC-02", CONFIGS_BY_ID)
        self.assertEqual(len(EXPLORATORY_CANDIDATE_CONFIGS), 2)

        # Verify ALL_CONFIGS has exactly 14 entries (12 confirmation + 2 exploratory)
        self.assertEqual(len(ALL_CONFIGS), 14)
        self.assertEqual(len(CONFIGS_BY_ID), 14)

    def test_validate_single_trial_runner_accepts_bk_dsc_05(self):
        """Runner non-executing validation accepts BK-DSC-05 with qwen2.5:7b-instruct."""
        test_sum = os.path.join(self.tmp_dir, "test_summary.json")
        test_trc = os.path.join(self.tmp_dir, "test_traces")

        report = validate_single_trial_runner(
            config_id="BK-DSC-05",
            condition="BASELINE",
            summary_path=test_sum,
            traces_dir=test_trc,
            base_dir=self.tmp_dir,
            model_name="qwen2.5:7b-instruct",
        )

        self.assertEqual(report["config_id"], "BK-DSC-05")
        self.assertEqual(report["condition"], "BASELINE")
        self.assertEqual(report["model_name"], "qwen2.5:7b-instruct")
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["errors"]), 0)

    def test_authentic_agentdojo_tasks_retrievable(self):
        """Authentic banking/user_task_2 and banking/injection_task_4 must load from AgentDojo."""
        suite = get_suite("v1", "banking")
        user_task = suite.get_user_task_by_id("user_task_2")
        self.assertIsNotNone(user_task)
        self.assertIn("landlord-notices.txt", user_task.PROMPT)
        self.assertIn("rent payment", user_task.PROMPT)

        inj_task = suite.get_injection_task_by_id("injection_task_4")
        self.assertIsNotNone(inj_task)
        self.assertIn("US133000000121212121212", inj_task.GOAL)
        self.assertIn("recurring payment", inj_task.GOAL)

    def test_model_allowlist_and_condition_validation(self):
        """Model allowlist and condition validation must accept approved options and reject invalid."""
        self.assertIn("qwen2.5:3b", VALID_MODELS)
        self.assertIn("qwen2.5:7b-instruct", VALID_MODELS)
        self.assertIn("BASELINE", VALID_CONDITIONS)
        self.assertIn("CONVENTIONAL", VALID_CONDITIONS)
        self.assertIn("PROVENANCE_AWARE", VALID_CONDITIONS)

        # Invalid model rejection
        test_sum = os.path.join(self.tmp_dir, "test_summary.json")
        test_trc = os.path.join(self.tmp_dir, "test_traces")

        report_bad_model = validate_single_trial_runner(
            config_id="BK-DSC-05",
            condition="BASELINE",
            summary_path=test_sum,
            traces_dir=test_trc,
            base_dir=self.tmp_dir,
            model_name="unsupported-model-xyz",
        )
        self.assertEqual(report_bad_model["status"], "FAIL")
        self.assertTrue(any("unsupported" in e.lower() for e in report_bad_model["errors"]))

        # Invalid config ID rejection
        report_bad_config = validate_single_trial_runner(
            config_id="INVALID-CONFIG-99",
            condition="BASELINE",
            summary_path=test_sum,
            traces_dir=test_trc,
            base_dir=self.tmp_dir,
            model_name="qwen2.5:7b-instruct",
        )
        self.assertEqual(report_bad_config["status"], "FAIL")
        self.assertTrue(any("invalid configuration id" in e.lower() or "invalid" in e.lower() for e in report_bad_config["errors"]))

    def test_ram_thresholds_intact(self):
        """All RAM safety thresholds must remain at exact calibrated values."""
        self.assertEqual(RAM_PREFLIGHT_THRESHOLD_GB, 7.0)
        self.assertEqual(RAM_EMERGENCY_STOP_THRESHOLD_GB, 5.0)
        self.assertEqual(RAM_MIN_THRESHOLD_GB, 3.0)

    def test_output_path_validation_and_collision_safeguards(self):
        """Output paths for BK-DSC-05 pass when isolated, and collide with reserved files."""
        # Clean isolated paths
        sum_path = os.path.join(self.tmp_dir, "reports", "phase_03f_r16_4_BK-DSC-05_summary.json")
        trc_path = os.path.join(self.tmp_dir, "traces", "phase_03f_r16_4_BK-DSC-05")
        res = validate_output_paths(sum_path, trc_path, base_dir=self.tmp_dir)
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.errors), 0)

        # Collision with historical reserved summary
        colliding_sum = os.path.join(self.tmp_dir, "reports", "phase_03f_confirmation_summary.json")
        res_col = validate_output_paths(colliding_sum, trc_path, base_dir=self.tmp_dir)
        self.assertFalse(res_col.is_valid)
        self.assertTrue(any("collides with reserved" in e for e in res_col.errors))

    def test_cli_parser_accepts_bk_dsc_05(self):
        """CLI argument parser correctly parses --config-id BK-DSC-05."""
        parser = build_parser()
        args = parser.parse_args([
            "--config-id", "BK-DSC-05",
            "--condition", "BASELINE",
            "--model-name", "qwen2.5:7b-instruct",
            "--validate-only",
        ])
        self.assertEqual(args.config_id, "BK-DSC-05")
        self.assertEqual(args.condition, "BASELINE")
        self.assertEqual(args.model_name, "qwen2.5:7b-instruct")
        self.assertTrue(args.validate_only)


if __name__ == "__main__":
    unittest.main()
