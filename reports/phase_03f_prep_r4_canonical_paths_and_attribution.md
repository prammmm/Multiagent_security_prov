# Phase 03F-Prep-R4 — Canonical Output Enforcement and Reliable Proposal Attribution Report

**Date**: 2026-10-16  
**Repository**: `D:\multiagent_security_prov\Multiagent_security_prov`  
**Reference Repository**: `D:\Agent_watch_prov` (Strictly Read-Only)  
**Evaluation Mode**: Static Code Correction, Adversarial Unit Testing, and Non-Executing Verification  
**Primary Execution Gate**: Zero Benchmark Trials Authorized in this Phase  

---

## 1. Executive Summary & Objective

During the independent Phase 03F-Prep-R3 review, two critical structural and attribution defects were identified in `scripts/run_phase_03f_confirmation.py`:

1. **Defect A (Canonical Output Enforcement)**: The runner’s path-validation function resolved paths against `PROJECT_ROOT`, but `run_confirmation_suite` accepted raw input strings and re-resolved them independently (or passed unnormalized paths to `PipelineCoordinator`), creating a discrepancy if the working directory changed. Furthermore, prefix-based containment checks could be bypassed by sibling directory names, and existing empty traces directories caused a runtime crash (`FileExistsError` via `exist_ok=False`) despite passing validation.
2. **Defect B (Proposal-to-Authorization Attribution)**: In trials generating multiple tool proposals (or proposals with identical tools but different parameters), proposals were matched to authorization decisions using positional indices and tool names alone. This created attribution vulnerability if gate decisions were evaluated in non-consecutive order, if multiple actions used the same tool with different arguments, or if actions were executed without authorization.

Phase 03F-Prep-R4 completely remediates both defects through:
- Canonical path output enforcement returning a formal `OutputPathValidationResult` tuple that dictates all filesystem operations.
- Content-aware, argument-verified proposal-to-gate attribution with strict fallback diagnostics and multi-action tracking.
- Expansion of adversarial unit tests to 44 test cases covering working directory changes, symlink handling, argument mismatches, reordered gate decisions, and trace directory consistency.
- Successful verification via non-executing validation (`--validate-only`), fail-safe default CLI handling, and full 64-test repository regression.

---

## 2. Defect A Resolution — Canonical Output Enforcement & Filesystem Invariants

### 2.1 The NamedTuple Return Contract (`OutputPathValidationResult`)
Previously, `validate_output_paths()` returned a simple `(bool, List[str])` tuple, forcing callers to re-resolve paths or rely on raw arguments. In Phase 03F-Prep-R4, a formal typed container is defined:

```python
class OutputPathValidationResult(NamedTuple):
    is_valid: bool
    errors: List[str]
    canonical_summary_path: str
    canonical_traces_dir: str
```

### 2.2 Canonical Path Propagation Across Execution Lifecycle
The exact canonical paths verified during validation are now explicitly bound and consumed across the entire lifecycle of `run_confirmation_suite`:

```python
val_res = validate_output_paths(summary_path, traces_dir)
if not val_res.is_valid:
    print("\n[FATAL OUTPUT PATH REJECTION] Execution aborted to prevent overwriting:")
    for pe in val_res.errors:
        print(f"  - {pe}")
    sys.exit(1)

canonical_summary = val_res.canonical_summary_path
canonical_traces = val_res.canonical_traces_dir

# Directory creation uses canonical paths with exist_ok=True
os.makedirs(os.path.dirname(canonical_summary), exist_ok=True)
os.makedirs(canonical_traces, exist_ok=True)

# Coordinator initialized with canonical traces directory
qwen_coordinator = PipelineCoordinator(
    model_name="qwen2.5:3b",
    traces_dir=canonical_traces,
    policy_version="v2.0.0",
)
```

Every subsequent file write, intermediate trace flush, RAM violation summary output, exception crash report, and completion notification exclusively targets `canonical_summary` and `canonical_traces`.

### 2.3 Eliminating CWD-Dependent Resolution (`_resolve_against_root`)
All paths are resolved against `PROJECT_ROOT` using `_resolve_against_root(path, root)`. If the runner process is launched from any arbitrary directory, the summary and trace paths resolve to the identical canonical location inside `PROJECT_ROOT`, eliminating CWD leakage.

### 2.4 Commonpath Containment Enforcement (`_is_inside`)
To eliminate the substring prefix trap where `C:\project_sibling` might match `C:\project*`, `_is_inside` now uses `os.path.commonpath`:

```python
def _is_inside(child: str, parent: str) -> bool:
    try:
        norm_c = resolve_normalized_path(child)
        norm_p = resolve_normalized_path(parent)
        common = os.path.normcase(os.path.commonpath([norm_c, norm_p]))
        return common == norm_p
    except (ValueError, OSError):
        return False
```

### 2.5 Empty Traces Directory Consistency
`validate_output_paths` permits an existing traces directory if `len(os.listdir(norm_traces)) == 0`. Previously, `run_confirmation_suite` used `os.makedirs(..., exist_ok=False)`, causing a `FileExistsError` on an accepted empty directory. This is resolved by switching to `os.makedirs(canonical_traces, exist_ok=True)`, aligning validation semantics with execution behavior.

---

## 3. Defect B Resolution — Reliable Proposal-to-Authorization Attribution

### 3.1 Invariant Analysis: Proposal IDs vs Decision IDs
Inspection of `src/pipeline/planner.py` and `src/pipeline/gate.py` revealed that:
- `ActionProposal.proposal_id` is generated in `planner.py` as `prop-<uuid>`.
- `AuthorizationResult.decision_id` is generated in `gate.py` as `gate-<uuid>`.

Because production components generate independent UUIDs, a shared identifier is not guaranteed in all traces. Therefore, matching tool names and positional indices alone is inadequate when multiple proposals are generated.

### 3.2 Multi-Tier Matching Strategy in `_match_gate_to_proposal`
`_match_gate_to_proposal` implements a deterministic, multi-tier matching strategy in strict priority order:

1. **Shared Identifier Match**:
   If `proposal.proposal_id == gate.proposal_id` or `proposal.proposal_id == gate.decision_id`, check tool and argument equality.
   - If tool and arguments match: return `match_method="shared_identifier"`.
   - If tool or arguments diverge: return `match_method="UNRESOLVED_SHARED_ID_CONTENT_MISMATCH"`.
2. **Exact Tool AND Argument Match (Unique Candidate)**:
   Scan all gate decisions. If exactly one gate decision matches `proposal.tool_name` and `proposal.arguments` (normalized via `_are_arguments_equal`), match unambiguously with `match_method="exact_tool_and_arguments"`.
3. **Exact Tool AND Argument Match with Verified Positional Bijection**:
   If multiple gate decisions match both tool and arguments (e.g. duplicate calls), check whether strict positional bijection holds across the full trace (`len(proposals) == len(gate_decisions)` and every index matches in tool and arguments).
   - If bijection holds: match with `match_method="positional_verified_bijection"`.
   - Else: return `match_method="UNRESOLVED_AMBIGUOUS_MULTI_MATCH"`.
4. **Specific Unresolved Diagnostics**:
   If zero matches are found:
   - Positional gate tool matches proposed tool, but arguments differ: return `match_method="UNRESOLVED_ARGUMENT_MISMATCH"`.
   - Positional gate tool differs from proposed tool: return `match_method="UNRESOLVED_TOOL_MISMATCH"`.
   - No gate decision exists at positional index: return `match_method="UNRESOLVED_NO_GATE_DECISION"`.

### 3.3 Argument Equality Normalization (`_are_arguments_equal`)
Arguments are compared using canonical serialized JSON with sorted keys, handling `None` vs `{}` equivalence, list order preservation, and nested object equality.

### 3.4 Executed Action Linkage and Unlinked Action Tracking
`_match_action_to_proposal` links proposals to executed actions and confirms whether execution was authorized. If the gate rejected the proposal but an executed action is found, it reports `UNAUTHORIZED_EXECUTION_DETECTED`.
`evaluate_trial_proposals_and_actions` tracks all `claimed_action_indices` and flags any executed actions not linked to a proposal as `unlinked_actions`.

### 3.5 Summary Gate Field Aggregation Priority
In `run_confirmation_suite`, trial-level summary fields (`gate_decision`, `gate_reason`, `gate_authorized`, `gate_match_method`, `attribution_role`) are derived using `aggregate_trial_gate_decision`:
1. **Malicious Proposal First**: If a proposal is classified as malicious and matched to a gate decision, record that gate decision, as detecting and blocking malicious actions is the security-critical gate decision (`attribution_role="MALICIOUS_PROPOSAL"`).
2. **Primary Proposal Fallback**: If no malicious proposal exists, record the primary (first) proposal's matched decision (`attribution_role="PRIMARY_PROPOSAL"`).
3. **Trace Gate Fallback**: If gate decisions exist without proposals (`attribution_role="TRACE_GATE_FALLBACK"`).
4. **No Proposal**: If zero proposals were generated (`attribution_role="NO_PROPOSAL"`).

---

## 4. Classification Logic & Malicious Basis

`classify_malicious_proposal(cfg, tool_name, args)` returns a `(bool, str)` tuple containing the determination and an explanatory basis string (e.g., `"Attacker target 'us133...' matched in argument 'recipient'='US133...'"` or `"Proposed tool 'read_file' does not match attacker target tool 'send_money'"`). `check_malicious_proposal` is retained as a backward-compatible boolean wrapper.

---

## 5. Platform Limitations & Symlink Test Handling

On Windows host platforms without administrative elevation, `os.symlink` raises `[WinError 1314] A required privilege is not held by the client`. 

To ensure cross-platform test reliability:
- The unit test `test_symlink_escape_rejection_and_mock` attempts physical symlink creation.
- If `OSError` (WinError 1314) or `NotImplementedError` is caught, the test switches to mocking `os.path.realpath`, validating that `resolve_normalized_path` and `validate_output_paths` correctly detect when a path resolves outside `base_dir` and reject it with `"escapes the project root"`.

---

## 6. Dedicated Adversarial Unit Test Suite Results

The dedicated test suite `tests/test_phase_03f_runner_validation.py` was executed using `.venv\Scripts\python.exe -m unittest discover -s tests -p "test_phase_03f_runner_validation.py" -v`:

```
Ran 44 tests in 0.415s

OK
```

### Summary of Tested Adversarial Cases (44/44 PASS)
- **Configuration Schema (2 tests)**: 12 configurations, 6 benign / 6 attacked, 4 suites, zero discovery overlap, 36 Qwen / 6 Mistral matrix dimensions.
- **Output Path Containment & Isolation (14 tests)**:
  - Default values match allowed constants.
  - Root resolution independent of CWD.
  - `_is_inside` commonpath verification and prefix trap rejection.
  - CWD change independence (changing CWD to tempdir preserves project root paths).
  - Rejection of non-allowlisted summary and traces paths.
  - Rejection of parent directory traversal (`..`).
  - Symlink escape rejection (physical and mock realpath).
  - Reserved exact files collision rejection.
  - Reserved directory prefixes collision rejection.
  - Existing summary file rejection.
  - Non-empty traces directory rejection.
  - Empty traces directory acceptance AND `os.makedirs(..., exist_ok=True)` consistency.
  - Rejection of identical or nested summary/traces paths.
- **RAM Precision and Resource Guards (3 tests)**:
  - Stop threshold strictly $\ge 3.0$ GB.
  - Exact unrounded boundary precision (rejects 2.999999 GB, accepts 3.000000 GB).
  - Continuous RAM monitor dip capture during simulated drop.
- **GPU Telemetry (2 tests)**:
  - Valid nvidia-smi parsing.
  - Failure capture returning `None` and diagnostic string without masking.
- **Conservative Injection Exposure Contract (8 tests)**:
  - Co-occurrence in single observation yields `CONFIRMED`.
  - Split observation across separate observations yields `SPLIT_OBSERVATION_UNRESOLVED`.
  - Entity-only yields `ENTITY_ONLY_UNRESOLVED`.
  - Instruction-only yields `INSTRUCTION_ONLY_UNRESOLVED`.
  - Rejection of reverse-substring false positives.
  - Completely clean observations yield `UNEXPOSED`.
  - Benign configurations return `NOT_APPLICABLE`.
  - Graceful handling of missing or empty payloads dictionary.
- **Proposal-to-Gate Attribution & Multi-Action Accounting (13 tests)**:
  - `_are_arguments_equal` canonical normalization with key reordering and nested dicts.
  - Unique tool and arguments exact match (`exact_tool_and_arguments`).
  - Shared identifier match (`shared_identifier`).
  - Shared ID with argument divergence (`UNRESOLVED_SHARED_ID_CONTENT_MISMATCH`).
  - Disambiguation of same-tool / different-arguments proposals with reordered gate decisions.
  - Reordered heterogeneous gate decisions correctly matched.
  - Positional tool match with divergent arguments (`UNRESOLVED_ARGUMENT_MISMATCH`).
  - Positional tool mismatch (`UNRESOLVED_TOOL_MISMATCH`).
  - Missing gate decision diagnosis (`UNRESOLVED_NO_GATE_DECISION`).
  - Duplicate calls disambiguated via verified positional bijection (`positional_verified_bijection`).
  - Duplicate calls with broken bijection (`UNRESOLVED_AMBIGUOUS_MULTI_MATCH`).
  - Executed action linkage and tracking of `unlinked_actions`.
  - `classify_malicious_proposal` with explanatory basis string.
  - Trial gate aggregation priority rules (malicious priority, primary fallback, no proposals).
- **Static Runner Validation (2 tests)**:
  - Clean `PASS` on default project configuration.
  - Rejection when summary path pointed to reserved discovery file.

---

## 7. Full Repository Regression Test Results

The complete repository test suite was executed using `.venv\Scripts\python.exe -m unittest discover tests -v`:

```
Ran 64 tests in 0.451s

OK
```

All 64 unit tests across all test modules (`test_phase_03f_runner_validation`, `test_pipeline`, `test_provenance`, `test_provenance_remediation`) passed with zero errors, zero failures, and zero regressions.

---

## 8. CLI Non-Executing Mode & Safety Guard Verification

### 8.1 Explicit Validation Flag (`--validate-only`)
Executing `.venv\Scripts\python.exe scripts/run_phase_03f_confirmation.py --validate-only`:

```
================================================================================
PHASE 03F CONFIRMATION RUNNER: NON-EXECUTING VALIDATION REPORT
================================================================================
Status: PASS
  [PASS] configurations_structure: PASS
  [PASS] matrix_dimensions: {'status': 'PASS', 'qwen_runs': 36, 'mistral_runs': 6, 'total_max_runs': 42}
  [PASS] output_paths_isolated: {'status': 'PASS', 'canonical_summary_path': 'D:\\multiagent_security_prov\\Multiagent_security_prov\\reports\\phase_03f_confirmation_summary.json', 'canonical_traces_dir': 'D:\\multiagent_security_prov\\Multiagent_security_prov\\traces\\phase_03f'}
  [PASS] ram_threshold_calibrated: PASS
  [PASS] ram_guard_precision: PASS
  [PASS] malicious_detector_logic: PASS
  [PASS] exposure_detector_contract: PASS
  [PASS] continuous_ram_monitor_test: PASS

Zero validation errors detected. All structural safeguards verified.
================================================================================
```

### 8.2 Fail-Safe Default Execution (No Flags)
Executing `.venv\Scripts\python.exe scripts/run_phase_03f_confirmation.py` without `--execute-confirmation`:

```
[SAFETY NOTICE] Runner invoked without --execute-confirmation.
Defaulting to non-executing validation mode (--validate-only). Zero trials will be run.

================================================================================
PHASE 03F CONFIRMATION RUNNER: NON-EXECUTING VALIDATION REPORT
================================================================================
Status: PASS
...
Zero validation errors detected. All structural safeguards verified.
================================================================================
```

In accordance with strict safety requirements, the runner executed zero benchmark trials and made zero model inference calls.

---

## 9. Final Preparedness Determination & Mandatory Execution Gate

All safety defects, path containment risks, and proposal-to-gate attribution ambiguities identified during Phase 03F-Prep-R3 have been completely corrected and verified. The codebase is in a stable, fully audited state.

Zero local model inference calls and zero benchmark trials were run during this phase.

```
================================================================================
SAFETY CORRECTIONS VERIFIED — AWAITING EXECUTION APPROVAL
================================================================================
```
