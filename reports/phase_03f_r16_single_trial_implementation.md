# Phase 03F R16 — Minimal Single-Trial Research Prototype Implementation Report

**Date**: 2026-10-17  
**Candidate Runner**: [`scripts/run_phase_03f_single_trial_r16.py`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16.py)  
**Dedicated Test Suite**: [`scripts/test_phase_03f_single_trial_r16.py`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16.py)  
**Candidate Safety Status**: `PROTOTYPE CANDIDATE — AWAITING STATIC REVIEW (EXECUTION LOCKED BY DEFAULT)`  
**Operational Policy**: Approved Best-Effort Resource Management (7.0 GiB dual-stage preflight checks, 5.0 GiB emergency stop with continuous 20 ms monitoring, simple tool dispatch interception, multi-stage streaming cancellation, safe telemetry exception handling, fail-closed monitor audit compliance, and 3.0 GiB non-compliant protocol violation floor).  

---

## 1. Executive Summary & Verification Verdict

| Verification Item | Implementation & Verification Details | Status |
|---|---|---|
| **Historical Candidate Preservation** | R8 through R15.2 remain completely unmodified. Reference repo `D:\Agent_watch_prov` is untouched. | **VERIFIED** |
| **Authentic Benchmark Integrity** | Tasks, prompts, injection payloads, scenarios, and ground truth from AgentDojo preserved without alteration. | **VERIFIED** |
| **Strict Single-Trial Scope** | At most ONE selected configuration under ONE condition per invocation. Matrix loops, automatic retries, and parallel execution are absent. | **VERIFIED** |
| **Qwen-Only Enforcement** | Strictly Qwen 2.5:3B (`qwen2.5:3b`). Mistral Nemo 12B is disallowed and rejected at initialization. | **VERIFIED** |
| **Dual Authorization Boundary** | Public API requires `execution_authorized=True` (raises `SingleTrialExecutionNotAuthorizedError` otherwise). CLI requires `--execute-single-trial`. Default invocation is validation only. | **VERIFIED** |
| **Practical RAM Safeguards** | Dual-stage 7.0 GiB preflight checks, target ~20 ms continuous RAM monitoring, 5.0 GiB emergency trigger, thread shutdown failure detection, and 3.0 GiB operating floor. | **VERIFIED** |
| **Attribution & Evidence Decoupling** | Unambiguously decouples injection exposure, tool proposal, authorization, tool dispatch, execution completion, environment mutation, and security breach. | **VERIFIED** |
| **Output Path Safeguards** | Dedicated R16 summary and traces paths. Prevents overwriting historical reports or non-empty trace directories. | **VERIFIED** |
| **Dedicated Mocked Unit Tests** | 25/25 dedicated mocked unit tests passing in 0.158s in `.venv`. Zero live Ollama calls, zero AgentDojo executions. | **VERIFIED** |
| **Final Implementation Verdict** | **`READY FOR STATIC REVIEW`** | **VERIFIED** |

---

## 2. Minimal Runner Architecture & Design

### 2.1 Reusing Existing Pipeline Interfaces
Rather than duplicating the 2,300+ lines of the matrix runner, `run_phase_03f_single_trial_r16.py` (~750 lines) directly reuses and extends the core architecture in `src/pipeline/`:
- **`PipelineCoordinator`**: Subclassed as `CancelablePipelineCoordinator` to inject streaming cancellation awareness across agents.
- **`OllamaClient`**: Subclassed as `CancelableStreamingOllamaClient` to support streaming HTTP token generation, multi-stage cancellation event checks, socket cleanup, and advisory model unloads (`keep_alive: 0`).
- **`FunctionsRuntime`**: Intercepted at dispatch time by `ToolDispatchGuard` to block downstream read-only and state-mutating tool executions when an emergency cancellation event is signaled.

### 2.2 Explicit Execution Authorization Boundary
Unlike R15.2's permanent unconditional execution lock, R16 implements an explicit authorization gate tailored for research prototype iteration:
1. **API Boundary**:
   ```python
   def run_single_trial(
       config_id: str,
       condition: str,
       execution_authorized: bool = False,
       summary_path: Optional[str] = None,
       traces_dir: Optional[str] = None,
       base_dir: Optional[str] = None,
   ) -> Dict[str, Any]:
       ...
       if not execution_authorized:
           raise SingleTrialExecutionNotAuthorizedError(
               "Explicit execution authorization required: execution_authorized must be set to True to dispatch a single trial."
           )
   ```
2. **CLI Boundary**:
   - `python scripts/run_phase_03f_single_trial_r16.py`: Defaults to non-executing validation mode (`validate_single_trial_runner`). Validates configuration ID, condition, output path containment/collision, and initial host RAM headroom. Exits with code 0 without constructing a live coordinator or contacting Ollama.
   - `python scripts/run_phase_03f_single_trial_r16.py --execute-single-trial --config-id <ID> --condition <COND>`: Required explicit opt-in for live trial execution.

### 2.3 Practical RAM Safeguards
- **Dual-Stage 7.0 GiB Preflight**:
  - *Stage 1*: Checks available host RAM before setting up the coordinator. If `< 7.0 GiB`, records a refusal summary (`REFUSED_PREFLIGHT_STAGE1`) and exits without coordinator initialization.
  - *Stage 2*: Re-evaluates available host RAM immediately before trial dispatch. If `< 7.0 GiB`, records a refusal summary (`REFUSED_PREFLIGHT_STAGE2`) and exits with 0 trials dispatched.
- **Continuous Monitoring & Emergency Trigger**:
  - Background thread polls `psutil.virtual_memory().available` at target ~20 ms intervals.
  - If available RAM drops below 5.0 GiB (`RAM_EMERGENCY_STOP_THRESHOLD_GB`), sets `cancellation_event` and records `emergency_stop_triggered = True`.
  - Thread shutdown timeout (1.0s) is monitored; failure to terminate flags `shutdown_failed = True` and marks the audit incomplete.
- **Fail-Closed Audit Invariants**:
  - Missing monitor (`ram_monitor is None`) -> `INCOMPLETE_AUDIT_MONITOR_MISSING`, non-compliant.
  - Unhealthy monitor (sampling errors) -> `INCOMPLETE_AUDIT_MONITOR_UNHEALTHY`, non-compliant.
  - Operating floor breach (`min_ram < 3.0 GiB` or `ram_after < 3.0 GiB`) -> `safety_protocol_violation: True`, non-compliant.

### 2.4 Evidence and Attribution Decoupling
The single-trial summary and trace explicitly isolate all 7 lifecycle phases:
1. `exposure_confirmed`: Confirmed observation of authentic injection instruction and attacker target in researcher observations.
2. `tool_proposed` & `arguments_proposed`: Tool and arguments emitted by the planner before authorization.
3. `gate_authorized`: Whether the Deterministic Authorization Boundary permitted the tool call.
4. `execution_attempted`: Whether tool execution was actually dispatched to the runtime.
5. `execution_completed`: Whether the runtime executed and returned without error.
6. `environment_mutated`: Whether state in the environment actually changed between pre-dispatch and post-dispatch snapshots.
7. `security_breach`: Whether AgentDojo's ground truth confirmed that the attacker's objective succeeded.

A denied proposal is strictly NOT a breach; tool proposal alone is NOT execution.

---

## 3. Static Findings vs. Tests Actually Executed

### 3.1 Static Code Analysis Findings
- **Single-Trial Constraint**: Inspected `run_phase_03f_single_trial_r16.py`. The execution path executes exactly one call to `coordinator.run_trial()`. There is no loop, retry logic, or multi-threading of trials.
- **Model Restrictions**: `CancelablePipelineCoordinator` strictly validates `model_name == "qwen2.5:3b"`. Any attempt to pass Mistral raises `ValueError`.
- **Preflight Gating**: Static verification of lines 555-608 confirms that both Stage 1 and Stage 2 preflight checks execute prior to `coordinator.run_trial()`, returning early with `trials_dispatched: 0` if RAM is insufficient.

### 3.2 Tests Actually Executed in `.venv` (Python 3.11)
Command executed:
```powershell
.\.venv\Scripts\python.exe -m unittest scripts/test_phase_03f_single_trial_r16.py -v
```

Complete Test Output:
```text
test_authorized_proposal_with_failed_execution (scripts.test_phase_03f_single_trial_r16.TestR16AttributionAndEvidenceDistinction.test_authorized_proposal_with_failed_execution)
Req 10: Authorized proposal whose execution fails does not mutate environment. ... ok
test_denied_proposal_is_not_a_breach (scripts.test_phase_03f_single_trial_r16.TestR16AttributionAndEvidenceDistinction.test_denied_proposal_is_not_a_breach)
Req 10: A denied tool proposal is NOT execution and NOT a security breach. ... ok
test_exposure_evaluation_distinguishes_attack_from_benign (scripts.test_phase_03f_single_trial_r16.TestR16AttributionAndEvidenceDistinction.test_exposure_evaluation_distinguishes_attack_from_benign)
Req 10: Injection exposure evaluation correctly labels attacked vs benign. ... ok
test_mutating_execution_with_and_without_breach (scripts.test_phase_03f_single_trial_r16.TestR16AttributionAndEvidenceDistinction.test_mutating_execution_with_and_without_breach)
Req 10: Environment mutation alone is not a breach unless ground truth confirms it. ... ok
test_emergency_signal_triggers_below_5_0_gib (scripts.test_phase_03f_single_trial_r16.TestR16EmergencyStopAndToolDispatchGuard.test_emergency_signal_triggers_below_5_0_gib)
Req 6: RAM dropping below 5.0 GiB triggers cancellation event. ... ok
test_streaming_client_aborts_before_dispatch_when_cancelled (scripts.test_phase_03f_single_trial_r16.TestR16EmergencyStopAndToolDispatchGuard.test_streaming_client_aborts_before_dispatch_when_cancelled)
Req 6: Streaming client aborts before network dispatch when cancellation event is set. ... ok
test_tool_dispatch_guard_blocks_when_cancellation_set (scripts.test_phase_03f_single_trial_r16.TestR16EmergencyStopAndToolDispatchGuard.test_tool_dispatch_guard_blocks_when_cancellation_set)
Req 6: ToolDispatchGuard intercepts and blocks tool execution if cancellation is set. ... ok
test_tool_dispatch_guard_passes_when_not_cancelled (scripts.test_phase_03f_single_trial_r16.TestR16EmergencyStopAndToolDispatchGuard.test_tool_dispatch_guard_passes_when_not_cancelled)
Req 6: ToolDispatchGuard allows execution when cancellation is not set. ... ok
test_api_rejects_unauthorized_call (scripts.test_phase_03f_single_trial_r16.TestR16InvocationAndAuthorization.test_api_rejects_unauthorized_call)
Req 3: API rejects calls without explicit execution authorization. ... ok
test_default_cli_invocation_is_validation_only (scripts.test_phase_03f_single_trial_r16.TestR16InvocationAndAuthorization.test_default_cli_invocation_is_validation_only)
Req 1: Default invocation performs validation only; never constructs coordinator or sends HTTP. ... ok
test_invalid_condition_rejected (scripts.test_phase_03f_single_trial_r16.TestR16InvocationAndAuthorization.test_invalid_condition_rejected)
Req 2: Invalid experimental conditions are rejected before setup. ... ok
test_invalid_config_id_rejected (scripts.test_phase_03f_single_trial_r16.TestR16InvocationAndAuthorization.test_invalid_config_id_rejected)
Req 2: Invalid configuration IDs are rejected before setup. ... ok
test_output_path_collides_with_reserved_artifact (scripts.test_phase_03f_single_trial_r16.TestR16OutputPathSafeguards.test_output_path_collides_with_reserved_artifact)
Req 9: Paths colliding with reserved historical reports are rejected. ... ok
test_output_path_escapes_root (scripts.test_phase_03f_single_trial_r16.TestR16OutputPathSafeguards.test_output_path_escapes_root)
Req 9: Paths outside the project root are rejected. ... ok
test_output_path_refuses_to_overwrite_existing_file (scripts.test_phase_03f_single_trial_r16.TestR16OutputPathSafeguards.test_output_path_refuses_to_overwrite_existing_file)
Req 9: Summary path validation refuses to overwrite existing files. ... ok
test_preflight_unrounded_boundary (scripts.test_phase_03f_single_trial_r16.TestR16PreflightRAMSafeguards.test_preflight_unrounded_boundary)
Req 5: Exact 7.0 GiB passes, 6.999999 GiB fails unrounded comparison. ... ok
test_stage1_preflight_refusal_when_below_7_0_gib (scripts.test_phase_03f_single_trial_r16.TestR16PreflightRAMSafeguards.test_stage1_preflight_refusal_when_below_7_0_gib)
Req 5: Stage 1 check (< 7.0 GiB) refuses execution before setup, dispatching 0 trials. ... ok
test_stage2_preflight_refusal_when_below_7_0_gib (scripts.test_phase_03f_single_trial_r16.TestR16PreflightRAMSafeguards.test_stage2_preflight_refusal_when_below_7_0_gib)
Req 5: Stage 2 check (< 7.0 GiB immediately before dispatch) halts execution. ... ok
test_coordinator_rejects_non_qwen_model (scripts.test_phase_03f_single_trial_r16.TestR16QwenOnlyRestriction.test_coordinator_rejects_non_qwen_model)
Req 2: CancelablePipelineCoordinator rejects non-Qwen models (Mistral disabled). ... ok
test_exactly_one_trial_dispatched (scripts.test_phase_03f_single_trial_r16.TestR16SingleTrialExecutionScope.test_exactly_one_trial_dispatched)
Req 4: Exactly one trial is dispatched per invocation. ... ok
test_evaluate_safety_missing_monitor_fails_closed (scripts.test_phase_03f_single_trial_r16.TestR16TelemetryAndComplianceEvaluation.test_evaluate_safety_missing_monitor_fails_closed)
Req 7: evaluate_trial_safety_and_compliance fails closed if ram_monitor is None. ... ok
test_evaluate_safety_monitor_shutdown_failed_fails_closed (scripts.test_phase_03f_single_trial_r16.TestR16TelemetryAndComplianceEvaluation.test_evaluate_safety_monitor_shutdown_failed_fails_closed)
Req 7: Monitor shutdown timeout marks audit incomplete and non-compliant. ... ok
test_evaluate_safety_monitor_unhealthy_fails_closed (scripts.test_phase_03f_single_trial_r16.TestR16TelemetryAndComplianceEvaluation.test_evaluate_safety_monitor_unhealthy_fails_closed)
Req 7: Unhealthy monitor marks audit incomplete and non-compliant. ... ok
test_evaluate_safety_operating_floor_violation (scripts.test_phase_03f_single_trial_r16.TestR16TelemetryAndComplianceEvaluation.test_evaluate_safety_operating_floor_violation)
Req 8: Measured RAM below 3.0 GiB marks a protocol violation and non-compliant. ... ok
test_safely_collect_post_trial_telemetry_catches_errors (scripts.test_phase_03f_single_trial_r16.TestR16TelemetryAndComplianceEvaluation.test_safely_collect_post_trial_telemetry_catches_errors)
Req 7: safely_collect_post_trial_telemetry catches monitor and psutil errors safely. ... ok

----------------------------------------------------------------------
Ran 25 tests in 0.158s

OK
```

### 3.3 Non-Executing Validation Command Output
Execution:
```powershell
.\.venv\Scripts\python.exe scripts/run_phase_03f_single_trial_r16.py --config-id BK-CNF-01 --condition PROVENANCE_AWARE
```
Output:
```text
[SAFETY NOTICE] Runner invoked without --execute-single-trial.
Defaulting to non-executing validation mode. Zero model calls, zero AgentDojo executions.

================================================================================
PHASE 03F R16: SINGLE-TRIAL RUNNER VALIDATION REPORT
================================================================================
Validation Status:     PASS
Config ID:             BK-CNF-01
Condition:             PROVENANCE_AWARE
Model:                 qwen2.5:3b (Qwen-only)
Host Available RAM:    3.2972 GiB (Preflight requirement: 7.0 GiB)
Preflight Headroom:    REFUSAL_ANTICIPATED
Summary Output:        D:\multiagent_security_prov\Multiagent_security_prov\reports\phase_03f_r16_single_trial_summary.json
Traces Destination:    D:\multiagent_security_prov\Multiagent_security_prov\traces\phase_03f_r16
Zero validation errors detected. All structural and parameter safeguards verified.
To execute this single trial, re-run with: --execute-single-trial
================================================================================
```

---

## 4. Remaining Technical & Architectural Limitations

1. **Non-Preemptible Blocking C Socket Reads**:
   - If the Ollama server stalls or the kernel encounters memory pressure while writing chunks, a thread blocked inside the synchronous C `recv()` socket call cannot be interrupted asynchronously by Python's `threading.Event`. Cancellation is checked immediately before and after read operations.
2. **Active Python Tool Execution Non-Preemptibility**:
   - Once a tool function is admitted and actively running synchronous Python code or an external library call within AgentDojo, user-space Python has no safe mechanism to forcibly abort that thread without risking interpreter corruption. `ToolDispatchGuard` intercepts subsequent dispatches, but cannot interrupt an in-flight tool.
3. **Out-of-Process Memory Deallocation Latency**:
   - Calling `attempt_unload(model)` sends an advisory RPC (`POST /api/generate` with `keep_alive: 0`) to `ollama.exe`. Immediate reclamation of physical RAM depends on the OS virtual memory manager and the separate Ollama process.
4. **Target 20 ms Polling Jitter**:
   - Polling intervals in `ContinuousRamMonitor` are software targets subject to Windows scheduling latency and GIL contention under high load.
5. **No Absolute RAM Floor Guarantee**:
   - In accordance with the approved best-effort policy, available RAM >= 3.0 GiB is enforced as a fail-closed protocol violation boundary and audit compliance requirement, not an impossible hardware guarantee.

---

## 5. Verification Invariants & Boundaries

1. **Zero Model Inference & Zero Ollama Invocations**:
   - All tests execute strictly in non-live, mocked unit environments.
   - `http://127.0.0.1:11434` was never contacted during test or validation execution.
2. **Zero Benchmark Trial Executions**:
   - Neither the confirmation matrix nor the single-trial pilot was executed.
   - `reports/phase_03f_r16_single_trial_summary.json` has not been generated or populated.
3. **Repository & Historical Candidate Immutability**:
   - Reference repository `D:\Agent_watch_prov` remains strictly read-only and unmodified.
   - Prior candidate scripts (`r8` through `r15_2`) and historical reports remain bit-for-bit unchanged.
4. **Execution Opt-In Requirement**:
   - Live trial execution is blocked unless `--execute-single-trial` is explicitly supplied at the CLI and `execution_authorized=True` is provided to `run_single_trial()`.

---

## 6. Deliverables & Final Verdict

- **Candidate Runner Artifact**: [`scripts/run_phase_03f_single_trial_r16.py`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/run_phase_03f_single_trial_r16.py)
- **Dedicated Test Suite Artifact**: [`scripts/test_phase_03f_single_trial_r16.py`](file:///D:/multiagent_security_prov/Multiagent_security_prov/scripts/test_phase_03f_single_trial_r16.py)
- **Implementation Report**: [`reports/phase_03f_r16_single_trial_implementation.md`](file:///D:/multiagent_security_prov/Multiagent_security_prov/reports/phase_03f_r16_single_trial_implementation.md)

```
================================================================================
FINAL VERDICT: READY FOR STATIC REVIEW
================================================================================
Phase 03F R16 successfully implements the minimal single-trial prototype runner:
1. Executes at most ONE selected configuration under ONE condition per invocation.
2. Qwen-only architecture with Mistral permanently disabled.
3. Explicit execution authorization boundary at API and CLI.
4. Approved best-effort RAM safeguards (7.0 GiB preflight, 5.0 GiB emergency trigger,
   3.0 GiB protocol floor) with fail-closed audit recording.
5. Strict attribution and evidence decoupling across all 7 lifecycle stages.
6. 25/25 dedicated mocked unit tests passing in 0.158s.
7. Zero benchmark trials executed; zero live model inference.
================================================================================
```
