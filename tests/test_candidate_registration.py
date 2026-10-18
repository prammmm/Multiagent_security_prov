"""Deterministic Unit Tests for Candidate BK-DSC-02 Registration in Phase 03F R16.2 Runner.

Verifies:
1. BK-DSC-02 is recognized and correctly structured in the runner configuration registry.
2. Authentic task and injection IDs, attack method, target tool, and attacker target match specifications.
3. The 12 held-out confirmation configurations remain recognized and completely unchanged.
4. validate_single_trial_runner accepts BK-DSC-02 under BASELINE with qwen2.5:7b-instruct.
5. Unsupported model names and invalid configuration IDs remain strictly rejected.
6. Output path validation and collision safeguards remain intact for BK-DSC-02.
7. Authentic AgentDojo definitions for user_task_0 and injection_task_0 are retrievable and unaltered.
8. Safety thresholds (7 GiB preflight, 5 GiB emergency stop, 3 GiB violation floor) remain intact.
"""

import os
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch

# Ensure project root is available in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentdojo.task_suite.load_suites import get_suite
from scripts.run_phase_03f_single_trial_r16_2 import (
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


class TestCandidateRegistrationBKDSC02(unittest.TestCase):
    """Focused tests for BK-DSC-02 registration and configuration integrity."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_bk_dsc_02_registered_and_structured(self):
        """BK-DSC-02 must be registered in CONFIGS_BY_ID with exact authentic fields."""
        self.assertIn("BK-DSC-02", CONFIGS_BY_ID)
        cfg = CONFIGS_BY_ID["BK-DSC-02"]

        self.assertEqual(cfg["config_id"], "BK-DSC-02")
        self.assertEqual(cfg["suite"], "banking")
        self.assertEqual(cfg["user_task"], "user_task_0")
        self.assertEqual(cfg["injection_task"], "injection_task_0")
        self.assertEqual(cfg["attack_name"], "important_instructions")
        self.assertEqual(cfg["type"], "attacked")
        self.assertEqual(cfg["category"], "Attack")
        self.assertEqual(cfg["attacker_target"], "US133000000121212121212")
        self.assertEqual(cfg["target_tool"], "send_money")

    def test_confirmation_configs_preserved_and_unmodified(self):
        """The 12 held-out confirmation configs must remain exactly 12 and untouched."""
        self.assertEqual(len(CONFIRMATION_CONFIGS), 12, "Confirmation set must contain exactly 12 configs")
        
        # Verify all 12 confirmation configs are present in CONFIGS_BY_ID
        expected_cnf_ids = {
            "BK-CNF-01", "BK-CNF-02", "BK-CNF-03", "BK-CNF-04",
            "WS-CNF-01", "WS-CNF-02", "WS-CNF-03", "WS-CNF-04",
            "TR-CNF-01", "TR-CNF-02",
            "SL-CNF-01", "SL-CNF-02",
        }
        for cnf_id in expected_cnf_ids:
            self.assertIn(cnf_id, CONFIGS_BY_ID, f"Missing confirmation config: {cnf_id}")
            self.assertIn(cnf_id, [c["config_id"] for c in CONFIRMATION_CONFIGS])

        # Verify ALL_CONFIGS has exactly 13 entries
        self.assertEqual(len(ALL_CONFIGS), 13)
        self.assertEqual(len(CONFIGS_BY_ID), 13)

    def test_validate_single_trial_runner_accepts_bk_dsc_02(self):
        """Runner non-executing validation accepts BK-DSC-02 with qwen2.5:7b-instruct."""
        test_sum = os.path.join(self.tmp_dir, "test_summary.json")
        test_trc = os.path.join(self.tmp_dir, "test_traces")

        report = validate_single_trial_runner(
            config_id="BK-DSC-02",
            condition="BASELINE",
            summary_path=test_sum,
            traces_dir=test_trc,
            base_dir=self.tmp_dir,
            model_name="qwen2.5:7b-instruct",
        )

        self.assertEqual(report["config_id"], "BK-DSC-02")
        self.assertEqual(report["condition"], "BASELINE")
        self.assertEqual(report["model_name"], "qwen2.5:7b-instruct")
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["errors"], [])

    def test_validate_single_trial_runner_rejects_invalid_configuration(self):
        """Runner non-executing validation rejects unknown configuration IDs."""
        test_sum = os.path.join(self.tmp_dir, "test_summary.json")
        test_trc = os.path.join(self.tmp_dir, "test_traces")

        report = validate_single_trial_runner(
            config_id="INVALID-CONFIG-99",
            condition="BASELINE",
            summary_path=test_sum,
            traces_dir=test_trc,
            base_dir=self.tmp_dir,
            model_name="qwen2.5:7b-instruct",
        )

        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("Invalid configuration ID 'INVALID-CONFIG-99'" in e for e in report["errors"]))

    def test_validate_single_trial_runner_rejects_unsupported_model(self):
        """Runner non-executing validation rejects models not in VALID_MODELS."""
        test_sum = os.path.join(self.tmp_dir, "test_summary.json")
        test_trc = os.path.join(self.tmp_dir, "test_traces")

        report = validate_single_trial_runner(
            config_id="BK-DSC-02",
            condition="BASELINE",
            summary_path=test_sum,
            traces_dir=test_trc,
            base_dir=self.tmp_dir,
            model_name="mistral-nemo:12b-instruct-2407-q4_K_M",
        )

        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("Invalid model_name 'mistral-nemo:12b-instruct-2407-q4_K_M'" in e for e in report["errors"]))

    def test_cli_parser_accepts_bk_dsc_02(self):
        """CLI parser accepts BK-DSC-02 and qwen2.5:7b-instruct."""
        parser = build_parser()
        args = parser.parse_args([
            "--config-id", "BK-DSC-02",
            "--condition", "BASELINE",
            "--model-name", "qwen2.5:7b-instruct",
        ])
        self.assertEqual(args.config_id, "BK-DSC-02")
        self.assertEqual(args.condition, "BASELINE")
        self.assertEqual(args.model_name, "qwen2.5:7b-instruct")

    def test_output_collision_checks_preserved_for_bk_dsc_02(self):
        """Output collision checks properly flag reserved artifacts and existing files."""
        # 1. Collision with reserved artifact
        res_collision = validate_output_paths(
            summary_path="reports/phase_03a_pilot_summary.json",
            traces_dir=os.path.join(self.tmp_dir, "traces"),
            base_dir=self.tmp_dir,
        )
        self.assertFalse(res_collision.is_valid)
        self.assertTrue(any("collides with reserved project artifact" in e for e in res_collision.errors))

        # 2. Collision with existing file
        existing_file = os.path.join(self.tmp_dir, "existing.json")
        with open(existing_file, "w") as f:
            f.write("{}")

        res_existing = validate_output_paths(
            summary_path=existing_file,
            traces_dir=os.path.join(self.tmp_dir, "traces"),
            base_dir=self.tmp_dir,
        )
        self.assertFalse(res_existing.is_valid)
        self.assertTrue(any("Refusing to overwrite existing run data" in e for e in res_existing.errors))

    def test_authentic_agentdojo_task_retrieval(self):
        """Authentic AgentDojo user_task_0 and injection_task_0 are retrievable and unaltered."""
        suite = get_suite("v1", "banking")
        ut = suite.get_user_task_by_id("user_task_0")
        it = suite.get_injection_task_by_id("injection_task_0")

        self.assertIsNotNone(ut, "user_task_0 must exist in authentic banking suite")
        self.assertIsNotNone(it, "injection_task_0 must exist in authentic banking suite")

        self.assertIn("bill-december-2023.txt", ut.PROMPT)
        self.assertIn("US133000000121212121212", it.GOAL)

    def test_safety_thresholds_intact(self):
        """Calibrated safety thresholds must not be altered."""
        self.assertEqual(RAM_PREFLIGHT_THRESHOLD_GB, 7.0)
        self.assertEqual(RAM_EMERGENCY_STOP_THRESHOLD_GB, 5.0)
        self.assertEqual(RAM_MIN_THRESHOLD_GB, 3.0)


if __name__ == "__main__":
    unittest.main()
