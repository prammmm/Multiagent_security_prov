"""Deterministic Unit Tests for Phase 03F R16.2 Runner Model Selection.

Verifies:
1. Default model remains 'qwen2.5:3b'.
2. Supported models list includes 'qwen2.5:3b' and 'qwen2.5:7b-instruct'.
3. CLI argument parser defaults to 'qwen2.5:3b' and accepts 'qwen2.5:7b-instruct'.
4. CLI parser rejects unsupported models (e.g. Mistral Nemo).
5. Validation runner reports the selected model and flags unsupported models.
6. CancelablePipelineCoordinator properly passes model_name to all internal agents and clients.
7. CancelablePipelineCoordinator and run_single_trial raise ValueError for unsupported models.
"""

import sys
import os
import unittest
import threading
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.run_phase_03f_single_trial_r16_2 import (
    VALID_MODELS,
    DEFAULT_MODEL,
    build_parser,
    validate_single_trial_runner,
    CancelablePipelineCoordinator,
    run_single_trial,
)


class TestModelSelection(unittest.TestCase):
    def test_default_model_and_valid_models(self):
        self.assertEqual(DEFAULT_MODEL, "qwen2.5:3b")
        self.assertIn("qwen2.5:3b", VALID_MODELS)
        self.assertIn("qwen2.5:7b-instruct", VALID_MODELS)
        self.assertNotIn("mistral-nemo:12b-instruct-2407-q4_K_M", VALID_MODELS)

    def test_parser_defaults_to_qwen2_5_3b(self):
        parser = build_parser()
        args = parser.parse_args(["--config-id", "WS-CNF-01", "--condition", "BASELINE"])
        self.assertEqual(args.model_name, "qwen2.5:3b")

    def test_parser_accepts_qwen2_5_7b_instruct(self):
        parser = build_parser()
        args = parser.parse_args([
            "--config-id", "WS-CNF-01",
            "--condition", "BASELINE",
            "--model-name", "qwen2.5:7b-instruct",
        ])
        self.assertEqual(args.model_name, "qwen2.5:7b-instruct")

    def test_parser_rejects_unsupported_model(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            # argparse prints error and exits with code 2 for invalid choices
            with patch("sys.stderr"):
                parser.parse_args([
                    "--config-id", "WS-CNF-01",
                    "--condition", "BASELINE",
                    "--model-name", "mistral-nemo:12b-instruct-2407-q4_K_M",
                ])

    def test_validate_single_trial_runner_default_model(self):
        report = validate_single_trial_runner(
            config_id="WS-CNF-01",
            condition="BASELINE",
            summary_path="reports/dummy_unused_summary.json",
            traces_dir="traces/dummy_unused_traces",
        )
        self.assertEqual(report["model_name"], "qwen2.5:3b")

    def test_validate_single_trial_runner_custom_model(self):
        report = validate_single_trial_runner(
            config_id="WS-CNF-01",
            condition="BASELINE",
            summary_path="reports/dummy_unused_summary.json",
            traces_dir="traces/dummy_unused_traces",
            model_name="qwen2.5:7b-instruct",
        )
        self.assertEqual(report["model_name"], "qwen2.5:7b-instruct")

    def test_validate_single_trial_runner_invalid_model(self):
        report = validate_single_trial_runner(
            config_id="WS-CNF-01",
            condition="BASELINE",
            summary_path="reports/dummy_unused_summary.json",
            traces_dir="traces/dummy_unused_traces",
            model_name="unsupported-model-tag",
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("Invalid model_name 'unsupported-model-tag'" in err for err in report["errors"]))

    def test_coordinator_model_wiring_qwen2_5_7b(self):
        event = threading.Event()
        coordinator = CancelablePipelineCoordinator(
            cancellation_event=event,
            model_name="qwen2.5:7b-instruct",
            traces_dir="traces/test_dummy_dir",
        )
        self.assertEqual(coordinator.model_name, "qwen2.5:7b-instruct")
        self.assertEqual(coordinator.client.default_model, "qwen2.5:7b-instruct")
        self.assertEqual(coordinator.cancelable_client.default_model, "qwen2.5:7b-instruct")
        self.assertEqual(coordinator.researcher.model_name, "qwen2.5:7b-instruct")
        self.assertEqual(coordinator.researcher.client.default_model, "qwen2.5:7b-instruct")
        self.assertEqual(coordinator.planner.model_name, "qwen2.5:7b-instruct")
        self.assertEqual(coordinator.planner.client.default_model, "qwen2.5:7b-instruct")

    def test_coordinator_unsupported_model_raises(self):
        event = threading.Event()
        with self.assertRaises(ValueError) as ctx:
            CancelablePipelineCoordinator(
                cancellation_event=event,
                model_name="llama3.2:3b",
                traces_dir="traces/test_dummy_dir",
            )
        self.assertIn("Phase 03F R16.2 supported models are", str(ctx.exception))

    def test_run_single_trial_invalid_model_raises(self):
        with self.assertRaises(ValueError) as ctx:
            run_single_trial(
                config_id="WS-CNF-01",
                condition="BASELINE",
                model_name="unsupported-model",
            )
        self.assertIn("Invalid model_name 'unsupported-model'", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
