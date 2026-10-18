"""Dedicated Mocked Unit and Safety Regression Tests for Phase 03F Confirmation Runner R15.2.

Validates the Phase 03F R15.2 Defect Remediations:
1. Missing Monitor Fail-Closed Enforcement:
   - evaluate_trial_safety_and_compliance() fails closed if ram_monitor is None or omitted.
   - Marks run strictly non-compliant and records INCOMPLETE_AUDIT_MONITOR_MISSING even with healthy RAM numbers.
2. Monitor Thread Shutdown Failure Detection:
   - ContinuousRamMonitor.stop() detects if its monitoring thread remains alive after join timeout (1.0s).
   - Records shutdown_failed=True, sets is_healthy=False, and logs explicit error.
   - Evaluator marks run non-compliant with INCOMPLETE_AUDIT_MONITOR_SHUTDOWN_FAILED.
3. Atomic Tool Dispatch Admission & Non-Blocking Synchronization:
   - ToolDispatchGuard uses dispatch_lock atomically for checking and admitting dispatches.
   - Lock is released before invoking orig_run_function, preventing monitor blocking during execution.
   - Verified that dispatch_lock is NOT held during active tool execution.
4. Correct Final-Chunk Branch Verification:
   - test_cancellation_when_final_response_chunk_arrives explicitly exercises the done: True branch
     (asserting 'on final done chunk') rather than being intercepted by the post-read check.
5. Non-Bypassable Execution Lock & Experimental Integrity:
   - run_confirmation_suite() unconditionally raises BenchmarkExecutionLockError.
   - Mutating module-level BENCHMARK_EXECUTION_LOCKED to False still refuses execution.
   - CLI rejects --execute-confirmation and --include-mistral.
   - Strictly Qwen-only (36 runs), sequential, zero live trials, zero Ollama daemon calls.
"""

import os
import sys
import json
import time
import tempfile
import threading
import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scripts.run_phase_03f_confirmation_r15_2 as r15_2
from scripts.run_phase_03f_confirmation_r15_2 import (
    CONFIRMATION_CONFIGS,
    CONDITIONS,
    MISTRAL_SUBSET_IDS,
    RAM_MIN_THRESHOLD_GB,
    RAM_EMERGENCY_STOP_THRESHOLD_GB,
    RAM_PREFLIGHT_THRESHOLD_GB,
    DEFAULT_SUMMARY_PATH,
    DEFAULT_TRACES_DIR,
    PROJECT_ROOT,
    ALLOWED_SUMMARY_PATH,
    ALLOWED_TRACES_DIR,
    EXECUTION_SAFETY_STATUS,
    BENCHMARK_EXECUTION_LOCKED,
    EXECUTION_LOCK_REASON,
    SAFETY_LIMITATION_DOCUMENTATION,
    BenchmarkExecutionLockError,
    InferenceCancelledEmergencyStopError,
    CancelableStreamingOllamaClient,
    ToolDispatchGuard,
    CancelablePipelineCoordinator,
    safely_collect_post_trial_telemetry,
    evaluate_trial_safety_and_compliance,
    OutputPathValidationResult,
    resolve_normalized_path,
    validate_output_paths,
    ContinuousRamMonitor,
    get_gpu_telemetry,
    evaluate_ram_headroom,
    classify_malicious_proposal,
    check_malicious_proposal,
    _are_arguments_equal,
    evaluate_injection_exposure,
    evaluate_trial_proposals_and_actions,
    aggregate_trial_gate_decision,
    match_proposals_to_gate_decisions_collection,
    match_proposals_to_actions_collection,
    validate_runner,
    init_summary_file,
    _safe_write_summary,
    run_confirmation_suite,
    main,
)
from src.pipeline.schema import EvaluationMode
from agentdojo.functions_runtime import FunctionsRuntime


class TestR152DefectRemediationFindings(unittest.TestCase):
    """Specifically verify the 4 required defect remediations in Phase 03F R15.2."""

    def test_evaluate_safety_missing_ram_monitor_fails_closed(self):
        """Finding 1: evaluate_trial_safety_and_compliance() fails closed if ram_monitor is missing.
        Even when numeric RAM measurements are present and healthy (>= 3.0 GiB),
        the result must be non-compliant and explicitly identify the incomplete monitoring audit.
        """
        eval_res = evaluate_trial_safety_and_compliance(
            min_ram_during=4.85,
            ram_after=5.20,
            ram_monitor=None,  # Monitor omitted or missing
            telemetry_errors=[],
            emergency_stop_exception=None,
            trial_exception=None,
        )

        self.assertFalse(eval_res["safety_protocol_compliant"], "Missing monitor must result in safety_protocol_compliant=False")
        self.assertTrue(eval_res["incomplete_audit"], "Missing monitor must result in incomplete_audit=True")
        self.assertEqual(eval_res["audit_status"], "INCOMPLETE_AUDIT_MONITOR_MISSING")
        self.assertIn("RESOURCE_MONITOR_MISSING", eval_res["stopping_reason"])
        self.assertFalse(eval_res["monitor_healthy"])

    def test_monitor_stop_detects_thread_shutdown_failure(self):
        """Finding 2: ContinuousRamMonitor.stop() detects when thread remains alive after timeout.
        Records shutdown_failed=True, sets is_healthy=False, and compliance evaluator marks
        the run non-compliant with INCOMPLETE_AUDIT_MONITOR_SHUTDOWN_FAILED.
        """
        monitor = ContinuousRamMonitor(interval_seconds=0.01)

        # Mock thread that remains alive despite join timeout
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True  # Thread fails to shut down
        monitor.thread = mock_thread
        monitor.min_ram_bytes = int(4.5 * (1024 ** 3))

        min_gb = monitor.stop()

        self.assertTrue(monitor.shutdown_failed, "shutdown_failed must be True when thread is alive after join")
        self.assertFalse(monitor.is_healthy, "is_healthy must be False on shutdown failure")
        self.assertTrue(any("failed to terminate within join timeout" in err for err in monitor.sampling_errors))

        # Check status dictionary
        status = monitor.get_status()
        self.assertTrue(status["shutdown_failed"])
        self.assertFalse(status["is_healthy"])

        # Pass monitor to compliance evaluator
        eval_res = evaluate_trial_safety_and_compliance(
            min_ram_during=min_gb,
            ram_after=4.6,
            ram_monitor=monitor,
        )
        self.assertFalse(eval_res["safety_protocol_compliant"])
        self.assertTrue(eval_res["incomplete_audit"])
        self.assertEqual(eval_res["audit_status"], "INCOMPLETE_AUDIT_MONITOR_SHUTDOWN_FAILED")
        self.assertIn("RESOURCE_MONITOR_SHUTDOWN_FAILURE", eval_res["stopping_reason"])

    def test_tool_dispatch_guard_atomic_admission_and_lock_release(self):
        """Finding 3: ToolDispatchGuard uses dispatch_lock atomically for check and admission,
        and releases the lock before calling orig_run_function so the monitor is never blocked.
        """
        orig_rt_func = FunctionsRuntime.run_function
        self.addCleanup(setattr, FunctionsRuntime, "run_function", orig_rt_func)

        cancel_event = threading.Event()
        dispatch_lock = threading.Lock()

        guard = ToolDispatchGuard(cancellation_event=cancel_event, dispatch_lock=dispatch_lock)

        lock_was_held_during_tool_execution = None

        class _MockEnv:
            pass

        class _MockTool:
            def __init__(self, name):
                self.name = name
                self.description = "Test tool"
                self.parameters = None

        env = _MockEnv()
        runtime = FunctionsRuntime([_MockTool("test_action")])

        def mock_tool_impl(rt_self, env, function, kwargs, raise_on_error=False):
            nonlocal lock_was_held_during_tool_execution
            # Check if dispatch_lock is locked while the tool function is actively executing
            lock_was_held_during_tool_execution = dispatch_lock.locked()
            return ("done", None)

        with guard:
            guard.orig_run_function = mock_tool_impl
            res, err = runtime.run_function(env, "test_action", {})
            self.assertEqual(res, "done")
            self.assertIsNone(err)

        # Proves the lock was NOT held during tool execution (monitor is never blocked)
        self.assertFalse(lock_was_held_during_tool_execution, "dispatch_lock must NOT be held during tool execution")
        self.assertEqual(guard.dispatches_accepted, 1)
        self.assertEqual(guard.dispatches_blocked, 0)

        # Now test that when cancellation is set, dispatch is blocked and counted
        cancel_event.set()
        with guard:
            with self.assertRaises(InferenceCancelledEmergencyStopError):
                runtime.run_function(env, "test_action", {})

        self.assertEqual(guard.dispatches_blocked, 1)

    @patch("urllib.request.urlopen")
    def test_cancellation_when_final_response_chunk_arrives(self, mock_urlopen):
        """Finding 4: Correct the final-chunk mocked test so it explicitly verifies the
        done: True branch ('on final done chunk') rather than being intercepted first
        by the post-read cancellation check.
        """
        mock_response = MagicMock()
        chunk1 = json.dumps({"response": "Beginning task... ", "done": False}).encode("utf-8") + b"\n"
        chunk_final = json.dumps({"response": "Task finished.", "done": True}).encode("utf-8") + b"\n"

        cancel_event = threading.Event()

        def readline_side_effect():
            if readline_side_effect.calls == 0:
                readline_side_effect.calls += 1
                return chunk1
            elif readline_side_effect.calls == 1:
                readline_side_effect.calls += 1
                # Return the final chunk line while cancel_event is STILL UNSET,
                # ensuring that post-read check passes!
                return chunk_final
            return b""

        readline_side_effect.calls = 0
        mock_response.readline.side_effect = readline_side_effect
        mock_urlopen.return_value = mock_response

        # Hook json.loads: when chunk_final is parsed (having done: True), set cancel_event!
        orig_json_loads = json.loads
        def hook_loads(s, *args, **kwargs):
            res = orig_json_loads(s, *args, **kwargs)
            if res.get("done") is True:
                cancel_event.set()  # Trip cancellation event exactly upon final chunk processing
            return res

        client = CancelableStreamingOllamaClient(
            default_model="qwen2.5:3b",
            cancellation_event=cancel_event,
        )

        with patch("json.loads", side_effect=hook_loads):
            with patch.object(client, "attempt_unload") as mock_unload:
                with self.assertRaises(InferenceCancelledEmergencyStopError) as ctx:
                    client.generate(prompt="Final chunk test")

                # EXPLICIT VERIFICATION: Must match 'on final done chunk' branch
                self.assertIn("on final done chunk", str(ctx.exception))
                mock_response.close.assert_called()
                self.assertTrue(client.last_response_closed)
                mock_unload.assert_called_with("qwen2.5:3b")


class TestR152ThresholdsAndPreflightSafeguards(unittest.TestCase):
    """Verify threshold constants and unrounded preflight evaluations."""

    def test_threshold_constants_values(self):
        """Req 1: Verify exact calibrated threshold values."""
        self.assertEqual(RAM_PREFLIGHT_THRESHOLD_GB, 7.0, "Preflight threshold must be exactly 7.0 GiB")
        self.assertEqual(RAM_EMERGENCY_STOP_THRESHOLD_GB, 5.0, "Emergency stop threshold must be exactly 5.0 GiB")
        self.assertEqual(RAM_MIN_THRESHOLD_GB, 3.0, "Operating floor must remain strictly 3.0 GiB")

    def test_preflight_exact_7_0_gib_passes(self):
        """Req 1: Exactly 7.0 GiB available passes preflight check."""
        bytes_7_0 = int(7.0 * (1024 ** 3))
        passed, val = evaluate_ram_headroom(bytes_7_0, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertTrue(passed)
        self.assertGreaterEqual(val, 7.0)

    def test_preflight_unrounded_6_999999_fails(self):
        """Req 1: 6.999999 GiB strictly fails the unrounded 7.0 GiB preflight check."""
        bytes_sub = int(6.999999 * (1024 ** 3))
        passed, val = evaluate_ram_headroom(bytes_sub, threshold_gb=RAM_PREFLIGHT_THRESHOLD_GB)
        self.assertFalse(passed)
        self.assertLess(val, 7.0)

    def test_operating_floor_unrounded_boundary(self):
        """Req 1: Operating floor 3.0 GiB unrounded evaluation."""
        bytes_below_3 = int(2.999999 * (1024 ** 3))
        passed_below, _ = evaluate_ram_headroom(bytes_below_3, threshold_gb=RAM_MIN_THRESHOLD_GB)
        self.assertFalse(passed_below)

        bytes_exact_3 = int(3.0 * (1024 ** 3))
        passed_exact, _ = evaluate_ram_headroom(bytes_exact_3, threshold_gb=RAM_MIN_THRESHOLD_GB)
        self.assertTrue(passed_exact)


class TestR152CancellationAndStreamingClient(unittest.TestCase):
    """Verify cancellation checks, chunk consumption, socket closure, and unload signaling."""

    @patch("urllib.request.urlopen")
    def test_cancellation_after_at_least_one_chunk_consumed(self, mock_urlopen):
        """Req 2: Simulate cancellation after at least one response chunk has actually been consumed."""
        mock_response = MagicMock()
        chunk1 = json.dumps({"response": "TokenChunk1 ", "done": False}).encode("utf-8") + b"\n"
        chunk2 = json.dumps({"response": "TokenChunk2", "done": False}).encode("utf-8") + b"\n"

        cancel_event = threading.Event()

        def readline_side_effect():
            if readline_side_effect.calls == 0:
                readline_side_effect.calls += 1
                return chunk1
            elif readline_side_effect.calls == 1:
                readline_side_effect.calls += 1
                cancel_event.set()  # Signal cancellation after chunk1 has been yielded/consumed
                return chunk2
            return b""

        readline_side_effect.calls = 0
        mock_response.readline.side_effect = readline_side_effect
        mock_urlopen.return_value = mock_response

        client = CancelableStreamingOllamaClient(
            default_model="qwen2.5:3b",
            cancellation_event=cancel_event,
        )

        with patch.object(client, "attempt_unload") as mock_unload:
            with self.assertRaises(InferenceCancelledEmergencyStopError) as ctx:
                client.generate(prompt="Analyze data")

            self.assertIn("post-read check", str(ctx.exception))
            mock_response.close.assert_called()
            self.assertTrue(client.last_response_closed)
            mock_unload.assert_called_with("qwen2.5:3b")

    @patch("urllib.request.urlopen")
    def test_cancellation_before_acceptance_of_completed_response(self, mock_urlopen):
        """Req 2: Test cancellation before accepting a completed response."""
        mock_response = MagicMock()
        chunk1 = json.dumps({"response": "Almost done", "done": False}).encode("utf-8") + b"\n"

        cancel_event = threading.Event()

        def readline_side_effect():
            if readline_side_effect.calls == 0:
                readline_side_effect.calls += 1
                return chunk1
            elif readline_side_effect.calls == 1:
                readline_side_effect.calls += 1
                cancel_event.set()
                return b""
            return b""

        readline_side_effect.calls = 0
        mock_response.readline.side_effect = readline_side_effect
        mock_urlopen.return_value = mock_response

        client = CancelableStreamingOllamaClient(
            default_model="qwen2.5:3b",
            cancellation_event=cancel_event,
        )

        with patch.object(client, "attempt_unload") as mock_unload:
            with self.assertRaises(InferenceCancelledEmergencyStopError) as ctx:
                client.generate(prompt="Test acceptance hook")

            self.assertIn("pre-acceptance check", str(ctx.exception))
            mock_response.close.assert_called()
            mock_unload.assert_called_with("qwen2.5:3b")

    @patch("urllib.request.urlopen")
    def test_cancellation_event_already_set_aborts_before_dispatch(self, mock_urlopen):
        """Req 2: If cancellation event is already set, client aborts before making HTTP request."""
        cancel_event = threading.Event()
        cancel_event.set()

        client = CancelableStreamingOllamaClient(
            default_model="qwen2.5:3b",
            cancellation_event=cancel_event,
        )

        with patch.object(client, "attempt_unload") as mock_unload:
            with self.assertRaises(InferenceCancelledEmergencyStopError) as ctx:
                client.generate(prompt="Test prompt")

            self.assertIn("Inference aborted before dispatch", str(ctx.exception))
            mock_urlopen.assert_not_called()
            mock_unload.assert_called_with("qwen2.5:3b")

    @patch("urllib.request.urlopen")
    def test_attempt_unload_request_structure(self, mock_urlopen):
        """Req 2: Best-effort attempt_unload issues POST to /api/generate with keep_alive: 0."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = CancelableStreamingOllamaClient(default_model="qwen2.5:3b")
        success = client.attempt_unload("qwen2.5:3b")

        self.assertTrue(success)
        self.assertTrue(client.unload_attempted)
        self.assertTrue(client.unload_success)

        req_arg = mock_urlopen.call_args[0][0]
        self.assertEqual(req_arg.full_url, "http://127.0.0.1:11434/api/generate")
        payload = json.loads(req_arg.data.decode("utf-8"))
        self.assertEqual(payload["model"], "qwen2.5:3b")
        self.assertEqual(payload["keep_alive"], 0)


    def test_cancelable_coordinator_aborts_before_trial_if_cancelled(self):
        """Req 2: CancelablePipelineCoordinator immediately aborts run_trial if cancellation is set."""
        cancel_event = threading.Event()
        cancel_event.set()

        coordinator = CancelablePipelineCoordinator(
            model_name="qwen2.5:3b",
            traces_dir=os.path.join(tempfile.gettempdir(), "test_traces"),
            cancellation_event=cancel_event,
        )

        with self.assertRaises(InferenceCancelledEmergencyStopError) as ctx:
            coordinator.run_trial(
                suite_name="banking",
                user_task_id="user_task_2",
                condition=EvaluationMode.BASELINE,
            )

        self.assertIn("Trial dispatch aborted: cancellation event set before trial start", str(ctx.exception))


class TestR152SafeTelemetryAndComplianceEvaluation(unittest.TestCase):
    """Verify safe telemetry handling and actual safety-decision and audit-recording functions."""

    def test_safely_collect_post_trial_telemetry_catches_all_failures(self):
        """Req 3: Test telemetry failure during exception handling."""
        mock_monitor = MagicMock()
        mock_monitor.stop.side_effect = RuntimeError("Deadlock in monitor thread join")

        with patch("psutil.virtual_memory", side_effect=OSError("WMI service unavailable")):
            min_during, ram_after, telem_errs = safely_collect_post_trial_telemetry(mock_monitor)

            self.assertIsNone(min_during)
            self.assertIsNone(ram_after)
            self.assertEqual(len(telem_errs), 2)
            self.assertIn("ram_monitor.stop() failed", telem_errs[0])
            self.assertIn("psutil.virtual_memory() post-trial query failed", telem_errs[1])

    def test_evaluate_safety_normal_compliant(self):
        """Req 3: Exercise actual safety-decision function: normal compliant run."""
        mock_monitor = MagicMock()
        mock_monitor.emergency_stop_triggered = False
        mock_monitor.is_healthy = True
        mock_monitor.failed_samples = 0
        mock_monitor.sampling_errors = []
        mock_monitor.shutdown_failed = False

        eval_res = evaluate_trial_safety_and_compliance(
            min_ram_during=4.25,
            ram_after=4.60,
            ram_monitor=mock_monitor,
            telemetry_errors=[],
            emergency_stop_exception=None,
            trial_exception=None,
        )

        self.assertFalse(eval_res["safety_protocol_violation"])
        self.assertTrue(eval_res["safety_protocol_compliant"])
        self.assertFalse(eval_res["incomplete_audit"])
        self.assertEqual(eval_res["audit_status"], "COMPLETE_AUDIT")
        self.assertIsNone(eval_res["stopping_reason"])
        self.assertIsNone(eval_res["original_error"])

    def test_evaluate_safety_protocol_floor_violation_during(self):
        """Req 3: Operating floor breach during trial marks violation and non-compliant."""
        mock_monitor = MagicMock()
        mock_monitor.emergency_stop_triggered = False
        mock_monitor.is_healthy = True
        mock_monitor.failed_samples = 0
        mock_monitor.shutdown_failed = False

        eval_res = evaluate_trial_safety_and_compliance(
            min_ram_during=2.85,
            ram_after=4.10,
            ram_monitor=mock_monitor,
            telemetry_errors=[],
        )

        self.assertTrue(eval_res["safety_protocol_violation"])
        self.assertFalse(eval_res["safety_protocol_compliant"])
        self.assertIn("SAFETY_PROTOCOL_VIOLATION_RAM_BELOW_MIN_FLOOR", eval_res["stopping_reason"])
        self.assertIn("2.8500 GiB", eval_res["stopping_reason"])

    def test_evaluate_safety_protocol_floor_violation_post(self):
        """Req 3: Operating floor breach post-flight marks violation and non-compliant."""
        mock_monitor = MagicMock()
        mock_monitor.emergency_stop_triggered = False
        mock_monitor.is_healthy = True
        mock_monitor.failed_samples = 0
        mock_monitor.shutdown_failed = False

        eval_res = evaluate_trial_safety_and_compliance(
            min_ram_during=3.50,
            ram_after=2.95,
            ram_monitor=mock_monitor,
            telemetry_errors=[],
        )

        self.assertTrue(eval_res["safety_protocol_violation"])
        self.assertFalse(eval_res["safety_protocol_compliant"])
        self.assertIn("SAFETY_PROTOCOL_VIOLATION_RAM_BELOW_MIN_FLOOR", eval_res["stopping_reason"])
        self.assertIn("2.9500 GiB", eval_res["stopping_reason"])

    def test_evaluate_safety_emergency_stop_triggered_marks_non_compliant(self):
        """Req 3: Emergency stop marks run non-compliant and records emergency stopping reason."""
        mock_monitor = MagicMock()
        mock_monitor.emergency_stop_triggered = True
        mock_monitor.emergency_reason = "Host available RAM dropped to 4.8 GiB"
        mock_monitor.is_healthy = True
        mock_monitor.failed_samples = 0
        mock_monitor.shutdown_failed = False

        eval_res = evaluate_trial_safety_and_compliance(
            min_ram_during=4.80,
            ram_after=4.90,
            ram_monitor=mock_monitor,
            emergency_stop_exception=InferenceCancelledEmergencyStopError("Emergency stop signaled"),
        )

        self.assertFalse(eval_res["safety_protocol_violation"])
        self.assertFalse(eval_res["safety_protocol_compliant"])
        self.assertTrue(eval_res["emergency_stop_triggered"])
        self.assertIn("RAM_EMERGENCY_STOP_TRIGGERED", eval_res["stopping_reason"])

    def test_evaluate_safety_monitor_unhealthy_marks_incomplete_and_non_compliant(self):
        """Req 3: Unhealthy monitor with sampling errors marks incomplete audit and non-compliant."""
        mock_monitor = MagicMock()
        mock_monitor.emergency_stop_triggered = False
        mock_monitor.is_healthy = False
        mock_monitor.failed_samples = 2
        mock_monitor.sampling_errors = ["Telemetry probe timeout", "Page fault query failed"]
        mock_monitor.shutdown_failed = False

        eval_res = evaluate_trial_safety_and_compliance(
            min_ram_during=5.5,
            ram_after=5.6,
            ram_monitor=mock_monitor,
        )

        self.assertFalse(eval_res["safety_protocol_compliant"])
        self.assertTrue(eval_res["incomplete_audit"])
        self.assertEqual(eval_res["audit_status"], "INCOMPLETE_AUDIT_MONITOR_UNHEALTHY")
        self.assertIn("RESOURCE_MONITOR_UNAVAILABLE", eval_res["stopping_reason"])
        self.assertFalse(eval_res["monitor_healthy"])

    def test_evaluate_safety_telemetry_failure_during_exception_handling(self):
        """Req 3: Test telemetry failure while processing another trial exception."""
        orig_exc = RuntimeError("Simulated crash inside AgentDojo environment")
        telem_errors = ["psutil.virtual_memory() post-trial query failed: OSError: device busy"]

        eval_res = evaluate_trial_safety_and_compliance(
            min_ram_during=None,
            ram_after=None,
            ram_monitor=None,
            telemetry_errors=telem_errors,
            trial_exception=orig_exc,
        )

        self.assertTrue(eval_res["incomplete_audit"])
        self.assertFalse(eval_res["safety_protocol_compliant"])
        self.assertEqual(eval_res["audit_status"], "INCOMPLETE_AUDIT_MONITOR_MISSING")
        self.assertIn("Simulated crash inside AgentDojo", eval_res["original_error"])
        self.assertEqual(eval_res["telemetry_errors"], telem_errors)


class TestR152ContinuousRamMonitor(unittest.TestCase):
    """Verify ContinuousRamMonitor 20ms polling, emergency signaling, and fail-closed telemetry."""

    @patch("psutil.virtual_memory")
    def test_emergency_signal_when_ram_below_5_0_gib(self, mock_vm):
        """Req 2: Monitor signals emergency stop when RAM drops below 5.0 GiB."""
        vm_good = MagicMock()
        vm_good.available = int(6.5 * (1024 ** 3))

        vm_low = MagicMock()
        vm_low.available = int(4.8 * (1024 ** 3))

        call_count = 0
        def vm_side_effect():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return vm_good
            return vm_low

        mock_vm.side_effect = vm_side_effect
        cancel_event = threading.Event()
        dispatch_lock = threading.Lock()
        monitor = ContinuousRamMonitor(
            interval_seconds=0.01,
            emergency_threshold_gb=5.0,
            cancellation_event=cancel_event,
            dispatch_lock=dispatch_lock,
        )
        monitor.start()
        time.sleep(0.06)
        min_gb = monitor.stop()

        status = monitor.get_status()
        self.assertTrue(monitor.emergency_stop_triggered)
        self.assertTrue(status["emergency_stop_triggered"])
        self.assertIn("EMERGENCY RAM HALT", monitor.emergency_reason)
        self.assertTrue(cancel_event.is_set())

    @patch("psutil.virtual_memory")
    def test_fail_closed_on_monitor_start_failure(self, mock_vm):
        """Req 2: Telemetry query failure during start() raises RuntimeError and flips health to False."""
        mock_vm.side_effect = OSError("WMI service unresponsive")
        cancel_event = threading.Event()
        monitor = ContinuousRamMonitor(interval_seconds=0.01, cancellation_event=cancel_event)
        with self.assertRaises(RuntimeError) as ctx:
            monitor.start()

        self.assertIn("ContinuousRamMonitor failed to query initial RAM", str(ctx.exception))
        self.assertFalse(monitor.is_healthy)
        self.assertEqual(len(monitor.sampling_errors), 1)
        self.assertTrue(cancel_event.is_set())

    @patch("psutil.virtual_memory")
    def test_fail_closed_on_mid_run_telemetry_failure(self, mock_vm):
        """Req 2: Telemetry query failure mid-monitoring sets is_healthy=False and signals cancellation."""
        vm_good = MagicMock()
        vm_good.available = int(7.5 * (1024 ** 3))

        def vm_side_effect():
            if mock_vm.call_count <= 2:
                return vm_good
            raise OSError("Kernel page telemetry failure")

        mock_vm.side_effect = vm_side_effect
        cancel_event = threading.Event()
        monitor = ContinuousRamMonitor(interval_seconds=0.01, cancellation_event=cancel_event)
        monitor.start()
        time.sleep(0.06)
        monitor.stop()

        self.assertFalse(monitor.is_healthy)
        self.assertGreater(monitor.failed_samples, 0)
        self.assertTrue(cancel_event.is_set())


class TestR152NonBypassableExecutionLock(unittest.TestCase):
    """Verify unconditional API lock and CLI rejection."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.summary_path = os.path.join(self.tmp_dir, "phase_03f_confirmation_summary.json")
        self.traces_dir = os.path.join(self.tmp_dir, "traces")
        os.makedirs(self.traces_dir, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_unauthorized_call_raises_execution_lock_error(self):
        """Req 5: Calling run_confirmation_suite(execution_authorized=False) raises BenchmarkExecutionLockError."""
        with self.assertRaises(BenchmarkExecutionLockError) as ctx:
            run_confirmation_suite(
                execution_authorized=False,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )
        self.assertIn("BENCHMARK EXECUTION IS LOCKED", str(ctx.exception))

    def test_authorized_call_raises_execution_lock_error(self):
        """Req 5: Calling run_confirmation_suite(execution_authorized=True) still raises BenchmarkExecutionLockError."""
        with self.assertRaises(BenchmarkExecutionLockError) as ctx:
            run_confirmation_suite(
                execution_authorized=True,
                summary_path=self.summary_path,
                traces_dir=self.traces_dir,
            )
        self.assertIn("BENCHMARK EXECUTION IS LOCKED", str(ctx.exception))

    @patch("scripts.run_phase_03f_confirmation_r15_2.validate_output_paths")
    @patch("src.pipeline.coordinator.PipelineCoordinator")
    def test_execution_refused_even_if_lock_variable_mutated_to_false(
        self, mock_coordinator_cls, mock_val_paths
    ):
        """Req 5: Mutating module-level BENCHMARK_EXECUTION_LOCKED to False does NOT bypass the lock."""
        mock_val_paths.return_value = OutputPathValidationResult(
            is_valid=True,
            errors=[],
            canonical_summary_path=self.summary_path,
            canonical_traces_dir=self.traces_dir,
        )
        original_lock_state = r15_2.BENCHMARK_EXECUTION_LOCKED
        try:
            r15_2.BENCHMARK_EXECUTION_LOCKED = False

            with self.assertRaises(BenchmarkExecutionLockError) as ctx:
                run_confirmation_suite(
                    execution_authorized=True,
                    summary_path=self.summary_path,
                    traces_dir=self.traces_dir,
                )
            self.assertIn("BENCHMARK EXECUTION IS LOCKED", str(ctx.exception))
            mock_coordinator_cls.assert_not_called()
            self.assertFalse(os.path.exists(self.summary_path))
        finally:
            r15_2.BENCHMARK_EXECUTION_LOCKED = original_lock_state

    def test_cli_rejects_execute_confirmation_flag(self):
        """Req 5: CLI invocation with --execute-confirmation invokes parser.error and exits."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r15_2.py", "--execute-confirmation"]):
            with self.assertRaises(SystemExit) as exit_ctx:
                main()
            self.assertNotEqual(exit_ctx.exception.code, 0)

    def test_cli_rejects_include_mistral_flag(self):
        """Req 5: CLI invocation with --include-mistral invokes parser.error and exits."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r15_2.py", "--include-mistral"]):
            with self.assertRaises(SystemExit) as exit_ctx:
                main()
            self.assertNotEqual(exit_ctx.exception.code, 0)

    def test_default_cli_invocation_remains_non_executing(self):
        """Req 5: Default CLI invocation runs validate_runner without launching trials."""
        with patch("sys.argv", ["run_phase_03f_confirmation_r15_2.py"]):
            with patch("scripts.run_phase_03f_confirmation_r15_2.validate_runner") as mock_validate:
                mock_validate.return_value = {"status": "PASS", "errors": []}
                with self.assertRaises(SystemExit) as exit_ctx:
                    main()
                self.assertEqual(exit_ctx.exception.code, 0)
                mock_validate.assert_called_once()


class TestR152ExperimentalIntegrityAndMatrix(unittest.TestCase):
    """Verify experimental matrix dimensions, safety constants, and path containment."""

    def test_strictly_qwen_only_matrix_dimensions(self):
        """Req 5: Strictly 36 Qwen runs planned; 0 Mistral runs."""
        report = validate_runner(verbose=False)
        self.assertEqual(report["status"], "PASS")
        matrix_check = report["checks"]["matrix_dimensions"]
        self.assertEqual(matrix_check["qwen_runs"], 36)
        self.assertEqual(matrix_check["mistral_runs"], 0)
        self.assertEqual(matrix_check["total_planned_runs"], 36)
        self.assertTrue(matrix_check["strictly_qwen_only"])

    def test_output_path_traversal_rejection(self):
        """Req 5: Path validation rejects traversal outside allowed destinations."""
        bad_summary = os.path.join(PROJECT_ROOT, "reports", "..", "secrets.json")
        res = validate_output_paths(bad_summary, ALLOWED_TRACES_DIR)
        self.assertFalse(res.is_valid)

    def test_safety_status_constants(self):
        """Req 1: Safety status constants reflect locked candidate status."""
        self.assertEqual(EXECUTION_SAFETY_STATUS, "NOT SAFE TO EXECUTE")
        self.assertTrue(BENCHMARK_EXECUTION_LOCKED)
        self.assertIn("BENCHMARK EXECUTION IS LOCKED", EXECUTION_LOCK_REASON)
        self.assertIn("NOT SAFE TO EXECUTE", SAFETY_LIMITATION_DOCUMENTATION)

    def test_attribution_identity_conflict_quarantined(self):
        """Req 5: Gate identity conflicts are quarantined and do not leak into signature matches."""
        class _MockProposal:
            def __init__(self, tool_name, arguments, proposal_id=None):
                self.tool_name, self.arguments, self.proposal_id = tool_name, arguments, proposal_id

        class _MockGate:
            def __init__(self, tool, args, decision_id=None, proposal_id=None, authorized=True):
                self.evaluated_tool, self.evaluated_arguments = tool, args
                self.decision_id, self.proposal_id = decision_id, proposal_id
                self.decision = "ALLOW" if authorized else "DENY"
                self.gate_authorized, self.reason = authorized, "identity collision test"

        p0 = _MockProposal("send_money", {"to": "alice", "amount": 5}, "prop-A")
        fake_link = _MockGate("send_money", {"to": "alice", "amount": 5}, decision_id="prop-A", proposal_id="unrelated-proposal")
        gate_attrs, unclaimed_gates = match_proposals_to_gate_decisions_collection([p0], [fake_link])
        self.assertFalse(gate_attrs[0]["matched"])
        self.assertTrue(unclaimed_gates[0]["identity_conflict"])


if __name__ == "__main__":
    unittest.main()
