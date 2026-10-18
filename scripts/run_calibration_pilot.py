"""Calibration pilot runner executing 16 controlled runs on qwen2.5:3b across AgentDojo."""

import os
import sys
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List, Dict, Any
from src.pipeline.schema import EvaluationMode
from src.pipeline.coordinator import PipelineCoordinator


PILOT_CONFIGS: List[Dict[str, Any]] = [
    # --- Workspace Benign (4 runs) ---
    {
        "id": "WS-BEN-01",
        "suite": "workspace",
        "user_task": "user_task_2",
        "injection_task": None,
        "condition": EvaluationMode.BASELINE,
    },
    {
        "id": "WS-BEN-02",
        "suite": "workspace",
        "user_task": "user_task_2",
        "injection_task": None,
        "condition": EvaluationMode.PROVENANCE_AWARE,
    },
    {
        "id": "WS-BEN-03",
        "suite": "workspace",
        "user_task": "user_task_8",
        "injection_task": None,
        "condition": EvaluationMode.CONVENTIONAL,
    },
    {
        "id": "WS-BEN-04",
        "suite": "workspace",
        "user_task": "user_task_8",
        "injection_task": None,
        "condition": EvaluationMode.PROVENANCE_AWARE,
    },
    # --- Workspace Attacked (4 runs) ---
    {
        "id": "WS-ATK-01",
        "suite": "workspace",
        "user_task": "user_task_2",
        "injection_task": "injection_task_0",
        "condition": EvaluationMode.BASELINE,
    },
    {
        "id": "WS-ATK-02",
        "suite": "workspace",
        "user_task": "user_task_2",
        "injection_task": "injection_task_0",
        "condition": EvaluationMode.PROVENANCE_AWARE,
    },
    {
        "id": "WS-ATK-03",
        "suite": "workspace",
        "user_task": "user_task_8",
        "injection_task": "injection_task_0",
        "condition": EvaluationMode.CONVENTIONAL,
    },
    {
        "id": "WS-ATK-04",
        "suite": "workspace",
        "user_task": "user_task_8",
        "injection_task": "injection_task_0",
        "condition": EvaluationMode.PROVENANCE_AWARE,
    },
    # --- Banking Benign (4 runs) ---
    {
        "id": "BK-BEN-01",
        "suite": "banking",
        "user_task": "user_task_0",
        "injection_task": None,
        "condition": EvaluationMode.BASELINE,
    },
    {
        "id": "BK-BEN-02",
        "suite": "banking",
        "user_task": "user_task_0",
        "injection_task": None,
        "condition": EvaluationMode.CONVENTIONAL,
    },
    {
        "id": "BK-BEN-03",
        "suite": "banking",
        "user_task": "user_task_0",
        "injection_task": None,
        "condition": EvaluationMode.PROVENANCE_AWARE,
    },
    {
        "id": "BK-BEN-04",
        "suite": "banking",
        "user_task": "user_task_2",
        "injection_task": None,
        "condition": EvaluationMode.PROVENANCE_AWARE,
    },
    # --- Banking Attacked (4 runs) ---
    {
        "id": "BK-ATK-01",
        "suite": "banking",
        "user_task": "user_task_0",
        "injection_task": "injection_task_0",
        "condition": EvaluationMode.BASELINE,
    },
    {
        "id": "BK-ATK-02",
        "suite": "banking",
        "user_task": "user_task_0",
        "injection_task": "injection_task_0",
        "condition": EvaluationMode.CONVENTIONAL,
    },
    {
        "id": "BK-ATK-03",
        "suite": "banking",
        "user_task": "user_task_0",
        "injection_task": "injection_task_0",
        "condition": EvaluationMode.PROVENANCE_AWARE,
    },
    {
        "id": "BK-ATK-04",
        "suite": "banking",
        "user_task": "user_task_2",
        "injection_task": "injection_task_0",
        "condition": EvaluationMode.PROVENANCE_AWARE,
    },
]


def main():
    print(f"=== Starting Direction B Calibration Pilot (16 Runs) ===")
    print(f"Model: qwen2.5:3b | Ollama Local Inference | AgentDojo v1")
    
    traces_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "traces")
    coordinator = PipelineCoordinator(
        model_name="qwen2.5:3b",
        traces_dir=traces_dir,
    )

    results_summary: List[Dict[str, Any]] = []

    start_all = time.perf_counter()

    for idx, cfg in enumerate(PILOT_CONFIGS, 1):
        print(f"\n[{idx}/16] Running {cfg['id']} -> Suite: {cfg['suite']} | Task: {cfg['user_task']} | Atk: {cfg['injection_task']} | Mode: {cfg['condition'].value}")
        
        try:
            trace = coordinator.run_trial(
                suite_name=cfg["suite"],
                user_task_id=cfg["user_task"],
                injection_task_id=cfg["injection_task"],
                condition=cfg["condition"],
            )

            gate_dec = trace.gate_decisions[0].decision.value if trace.gate_decisions else "NO_GATE"
            tool_prop = trace.proposals[0].tool_name if trace.proposals else "none"
            duration = trace.system_metrics.get("wall_clock_seconds", 0.0)

            rec = {
                "index": idx,
                "config_id": cfg["id"],
                "suite": cfg["suite"],
                "user_task": cfg["user_task"],
                "injection_task": cfg["injection_task"],
                "condition": cfg["condition"].value,
                "proposed_tool": tool_prop,
                "gate_decision": gate_dec,
                "action_executed": bool(trace.executed_actions),
                "utility_success": trace.utility_success,
                "security_breach": trace.security_breach,
                "wall_clock_seconds": duration,
                "ram_available_gb": trace.system_metrics.get("system_available_ram_gb_after"),
                "run_id": trace.run_id,
            }
            results_summary.append(rec)

            print(f"    Result: Gate={gate_dec} | Exec={rec['action_executed']} | Util={trace.utility_success} | Breach={trace.security_breach} | Time={duration}s")
        except Exception as e:
            print(f"    ERROR running {cfg['id']}: {e}")
            results_summary.append({
                "index": idx,
                "config_id": cfg["id"],
                "suite": cfg["suite"],
                "user_task": cfg["user_task"],
                "condition": cfg["condition"].value,
                "error": str(e),
            })

    total_time = round(time.perf_counter() - start_all, 2)
    print(f"\n=== Pilot Complete: 16/16 Runs Finished in {total_time}s ===")

    # Write summary report
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    summary_path = os.path.join(reports_dir, "calibration_pilot_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({"total_time_seconds": total_time, "runs": results_summary}, f, indent=2)

    print(f"Summary JSON saved to: {summary_path}")


if __name__ == "__main__":
    main()
