# Phase 03F R16.6 — Condition-Isolated Output Paths Implementation Report

**Project:** `D:\multiagent_security_prov\Multiagent_security_prov`  
**Pipeline Version:** `R16.6`  
**Strategy:** `hardened_handoff_v4` + Recipient-Omission Planner Guidance  
**Target Configuration:** `BK-DSC-05` (`banking`, `user_task_2`, `injection_task_4`, `important_instructions`)  
**Target Model:** `qwen2.5:7b-instruct`  
**Execution Status:** NON-EXECUTING (Zero trial executions, zero Ollama inference calls)

---

## 1. Executive Summary

To enable a fair, sequential, and unpolluted experimental comparison of all three authorization conditions (`BASELINE`, `CONVENTIONAL`, and `PROVENANCE_AWARE`) under Phase 03F R16.6, the single-trial runner has been upgraded with automated, condition-isolated canonical output paths and enhanced collision safeguards.

Previously, running without explicit CLI destination flags defaulted to a generic destination (`reports/phase_03f_r16_6_single_trial_summary.json` and `traces/phase_03f_r16_6`), creating a risk of accidental overwrites or collisions between sequential condition runs.

Under the new implementation:
1. Output paths are deterministically and automatically derived from `(config_id, condition, model_name)`.
2. All three authorization conditions generate strictly distinct, non-overlapping file and directory paths.
3. Overwrite protection ensures existing run records are never overwritten.
4. Cross-condition mismatch checks prevent accidental destination pollution.
5. All historical R16.2, R16.3, R16.4, and R16.5 summary files and trace directory prefixes remain fully protected.
6. Calibrated RAM thresholds (7.0 GiB preflight, 5.0 GiB emergency stop, 3.0 GiB audit floor) remain untouched.

---

## 2. Canonical Path Derivation & Specifications

### 2.1 Model Identifier Sanitization
Model names are normalized into filesystem-safe suffixes via `sanitize_model_identifier()`:
- `qwen2.5:7b-instruct` $\rightarrow$ `qwen2_5_7b`
- `qwen2.5:3b` $\rightarrow$ `qwen2_5_3b`

### 2.2 Canonical Path Formula
For any configuration $C \in \text{ALL\_CONFIGS}$, condition $K \in \{\text{BASELINE}, \text{CONVENTIONAL}, \text{PROVENANCE\_AWARE}\}$, and model $M \in \text{VALID\_MODELS}$:
- **Summary Report:** `reports/phase_03f_r16_6_{C}_{K}_{M_sanitized}_summary.json`
- **Traces Directory:** `traces/phase_03f_r16_6_{C}_{K}_{M_sanitized}/`

### 2.3 Condition Paths for BK-DSC-05 with qwen2.5:7b-instruct

| Condition | Summary Destination | Traces Directory Destination |
| :--- | :--- | :--- |
| **BASELINE** | `reports/phase_03f_r16_6_BK-DSC-05_BASELINE_qwen2_5_7b_summary.json` | `traces/phase_03f_r16_6_BK-DSC-05_BASELINE_qwen2_5_7b/` |
| **CONVENTIONAL** | `reports/phase_03f_r16_6_BK-DSC-05_CONVENTIONAL_qwen2_5_7b_summary.json` | `traces/phase_03f_r16_6_BK-DSC-05_CONVENTIONAL_qwen2_5_7b/` |
| **PROVENANCE_AWARE** | `reports/phase_03f_r16_6_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b_summary.json` | `traces/phase_03f_r16_6_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b/` |

All 14 configurations (12 confirmation + 2 exploratory) across 3 conditions and 2 models yield $14 \times 3 \times 2 = 84$ pairwise-disjoint summary paths and 84 pairwise-disjoint trace directories.

---

## 3. Defense-in-Depth Path Safeguards

`validate_output_paths()` has been enhanced with multi-layered integrity checks:

1. **Explicit Path Traversal Guard:**
   Detects raw traversal sequences (`..`) in both summary and trace paths, refusing paths before filesystem resolution.
2. **Project Root Containment:**
   Ensures canonical paths resolve strictly within the project root (`_is_inside(path, PROJECT_ROOT)`).
3. **Format & Suffix Validation:**
   Summary destinations must be valid `.json` files.
4. **Collision with Historical Artifacts:**
   - `RESERVED_EXACT_FILES`: Extended to include all R16.2–R16.5 summaries (including `phase_03f_r16_5_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b_summary.json` and R16.4 confirmation summaries).
   - `RESERVED_DIRECTORY_PREFIXES`: Protects all historical trace directories (`phase_03f_confirmation`, `phase_03f_r16`, `phase_03f_r16_1`, `phase_03f_r16_2`, `phase_03f_r16_3`, `phase_03f_r16_4`, `phase_03f_r16_5`).
5. **Cross-Condition Alignment Guard:**
   When a trial targets a specific condition (e.g. `BASELINE`), passing a path specifying another condition (e.g. `_CONVENTIONAL_` or `_PROVENANCE_AWARE_`) is caught as a condition mismatch error.
6. **Overwrite Protection:**
   - Refuses dispatch if summary file already exists.
   - Refuses dispatch if trace directory already exists and is non-empty.
   - Ensures completed runs for one condition do not block or pollute another condition.

---

## 4. Verification & Test Evidence

### 4.1 Test Suites Executed

```bash
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_phase_03f_r16_6_*.py"
```

**Results:**
```
..................
----------------------------------------------------------------------
Ran 18 tests in 0.594s

OK
```

- **`test_phase_03f_r16_6_planner_guidance.py`** (6 tests): All PASSED.
  - Strict preservation of R16.6 planner guidance (omits `recipient` on rent adjustments).
  - Authentic task structure and tool definitions intact.
  - Strict provenance gate intact.
- **`test_phase_03f_r16_6_condition_isolation.py`** (12 tests): All PASSED.
  - Distinct paths across BASELINE, CONVENTIONAL, and PROVENANCE_AWARE.
  - Global pairwise uniqueness across 84 path combinations.
  - Overwrite refusal for existing summary files and non-empty trace directories.
  - Sequential independence across conditions.
  - Cross-condition mismatch rejection.
  - Path traversal and root escape rejection.
  - Protection of historical R16.2–R16.5 files and directory prefixes.
  - Preservation of RAM thresholds (7.0 / 5.0 / 3.0 GiB).

### 4.2 Non-Executing Runner Output Verification

All three conditions were verified using the single-trial runner CLI without `--execute-single-trial`:

1. **BASELINE:**
   ```
   Summary Output:     reports\phase_03f_r16_6_BK-DSC-05_BASELINE_qwen2_5_7b_summary.json
   Traces Destination: traces\phase_03f_r16_6_BK-DSC-05_BASELINE_qwen2_5_7b
   Status:             PASS (Zero validation errors detected)
   ```
2. **CONVENTIONAL:**
   ```
   Summary Output:     reports\phase_03f_r16_6_BK-DSC-05_CONVENTIONAL_qwen2_5_7b_summary.json
   Traces Destination: traces\phase_03f_r16_6_BK-DSC-05_CONVENTIONAL_qwen2_5_7b
   Status:             PASS (Zero validation errors detected)
   ```
3. **PROVENANCE_AWARE:**
   ```
   Summary Output:     reports\phase_03f_r16_6_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b_summary.json
   Traces Destination: traces\phase_03f_r16_6_BK-DSC-05_PROVENANCE_AWARE_qwen2_5_7b
   Status:             PASS (Zero validation errors detected)
   ```

### 4.3 Zero Inference & Zero Trial Dispatch Confirmation
- No trial executions were dispatched (`--execute-single-trial` was never invoked).
- No Ollama model calls were made.
- Disk verification confirmed zero destination summaries or trace directories were created.
- Working copy remains clean with all historical evidence intact.
