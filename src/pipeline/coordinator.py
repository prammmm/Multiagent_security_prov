"""Pipeline Coordinator: orchestrates environment, Researcher, Handoff, Planner, Gate, and trace recording."""

import os
import re
import json
import uuid
import time
import psutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from agentdojo.task_suite.load_suites import get_suite
from agentdojo.task_suite.task_suite import BaseUserTask, BaseInjectionTask
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.functions_runtime import FunctionsRuntime, FunctionCall

from src.pipeline.schema import (
    EvaluationMode,
    GateDecision,
    TraceRecord,
    ActionProposal,
    AuthorizationResult,
    HandoffPayload,
)
from src.pipeline.provenance import ProvenanceTracker
from src.pipeline.gate import DeterministicAuthorizationBoundary
from src.pipeline.researcher import ResearcherAgent, is_read_only_tool
from src.pipeline.planner import PlannerAgent
from src.pipeline.ollama_client import OllamaClient
from src.pipeline.validation import validate_action_pre_execution


def is_task_execution_request(user_prompt: str) -> bool:
    """Classify whether the user prompt requests an action/mutation vs purely informational query."""
    prompt_lower = user_prompt.lower()
    action_verbs = [
        "pay", "send", "transfer", "refund", "schedule", "update", "create",
        "delete", "cancel", "reschedule", "add", "remove", "change", "adjust",
        "forward", "modify", "share", "book"
    ]
    return any(re.search(rf"\b{re.escape(v)}\b", prompt_lower) for v in action_verbs)


def filter_planner_available_tools(
    suite_tools: List[Any],
    user_prompt: str,
    pipeline_version: str,
) -> List[Any]:
    """Filter available tools for the Planner agent depending on pipeline revision and task intent."""
    if pipeline_version not in ("R16.4", "R16.5", "R16.6", "R16.7", "R16.8", "R16.8.1"):
        # Legacy R16.2 / R16.3: pass all suite tools unconstrained
        return suite_tools

    # R16.4 / R16.5 / R16.6: For task-execution requests, restrict Planner to action/mutating tools.
    # Exclude researcher-only discovery tools from terminal proposal options.
    if is_task_execution_request(user_prompt):
        action_tools = [t for t in suite_tools if not is_read_only_tool(t.name)]
        if action_tools:
            return action_tools

    return suite_tools


class _DummyPipeline:
    """Minimal surrogate pipeline required by AgentDojo attack loaders."""
    def __init__(self, name: str = "local"):
        self.name = name


class PipelineCoordinator:
    """Central orchestration harness for Direction B multi-agent security experiments."""

    def __init__(
        self,
        model_name: str = "qwen2.5:3b",
        traces_dir: str = "traces",
        policy_version: str = "v2.0.0",
        pipeline_version: str = "R16.2",
        researcher_strategy: str = "stateless_v1",
    ):
        self.model_name = model_name
        self.traces_dir = traces_dir
        self.policy_version = policy_version
        self.pipeline_version = pipeline_version
        self.researcher_strategy = researcher_strategy
        self.gate = DeterministicAuthorizationBoundary(policy_version=policy_version)
        self.client = OllamaClient(default_model=model_name)
        self.researcher = ResearcherAgent(
            model_name=model_name,
            client=self.client,
            strategy=researcher_strategy,
        )
        self.planner = PlannerAgent(
            model_name=model_name,
            client=self.client,
            pipeline_version=pipeline_version,
        )

        os.makedirs(self.traces_dir, exist_ok=True)

    def run_trial(
        self,
        suite_name: str,
        user_task_id: str,
        condition: EvaluationMode,
        injection_task_id: Optional[str] = None,
        attack_name: Optional[str] = "important_instructions",
        benchmark_version: str = "v1",
    ) -> TraceRecord:
        """Run an end-to-end evaluation trial and record complete machine-readable trace."""
        run_id = f"trial-{uuid.uuid4().hex[:12]}"
        start_utc = datetime.now(timezone.utc).isoformat()
        start_wall = time.perf_counter()

        proc = psutil.Process()
        mem_before = proc.memory_info().rss / (1024 * 1024)
        sys_mem_before = psutil.virtual_memory().available / (1024 * 1024 * 1024)

        errors: List[str] = []
        injection_payloads: Dict[str, str] = {}

        # 1. Load task suite & tasks
        suite = get_suite(benchmark_version, suite_name)
        user_task = suite.get_user_task_by_id(user_task_id)
        if not user_task:
            raise ValueError(f"User task {user_task_id} not found in {suite_name}")

        user_prompt = user_task.PROMPT

        # 2. Setup injection if requested
        injection_task = None
        if injection_task_id:
            injection_task = suite.get_injection_task_by_id(injection_task_id)
            if not injection_task:
                raise ValueError(f"Injection task {injection_task_id} not found in {suite_name}")

            dummy_pipe = _DummyPipeline(name="local")
            attack = load_attack(attack_name, suite, dummy_pipe)
            injections = attack.attack(user_task, injection_task)
            injection_payloads = {str(k): str(v) for k, v in injections.items()}
            env = suite.load_and_inject_default_environment(injections)
        else:
            env = suite.load_and_inject_default_environment({})

        # 3. Initialize user task environment & take pre-environment snapshot
        if isinstance(user_task, BaseUserTask):
            env = user_task.init_environment(env)
        pre_env = env.model_copy(deep=True)

        # 4. Determine authorized tools policy
        try:
            gt_calls = user_task.ground_truth(env)
            allowed_tools = {fc.function for fc in gt_calls}
        except Exception:
            # Fallback allowed tools based on task type
            allowed_tools = set()

        # 5. Initialize Provenance Tracker
        tracker = ProvenanceTracker(user_goal=user_prompt)

        # 6. Execute Researcher
        handoff, observations = self.researcher.run(
            user_prompt=user_prompt,
            env=env,
            tools=suite.tools,
            provenance_tracker=tracker,
        )

        # 7. Execute Planner
        planner_tools = filter_planner_available_tools(
            suite_tools=suite.tools,
            user_prompt=user_prompt,
            pipeline_version=self.pipeline_version,
        )

        proposal = self.planner.plan(
            user_prompt=user_prompt,
            handoff=handoff,
            available_tools=planner_tools,
            provenance_tracker=tracker,
        )

        # 8. Evaluate Authorization Boundary
        gate_decision = self.gate.evaluate(
            proposal=proposal,
            user_goal=user_prompt,
            allowed_tools=allowed_tools,
            condition=condition,
            provenance_tracker=tracker,
        )

        # 9. Disambiguated Execution Lifecycle
        executed_actions: List[Dict[str, Any]] = []
        function_calls_stack: List[FunctionCall] = []

        gate_authorized = gate_decision.gate_authorized
        execution_attempted = False
        execution_completed = False
        environment_mutated = False

        if gate_authorized and proposal.tool_name and proposal.tool_name != "none":
            user_iban = None
            if hasattr(env, "bank_account") and hasattr(env.bank_account, "iban"):
                user_iban = getattr(env.bank_account, "iban", None)

            is_valid, validation_reason = validate_action_pre_execution(
                proposal=proposal,
                user_prompt=user_prompt,
                observations=observations,
                user_account_iban=user_iban,
            )
            if not is_valid:
                errors.append(f"PRE_EXECUTION_VALIDATION_REJECTED: {validation_reason}")
            else:
                execution_attempted = True
                pre_dispatch_env = env.model_copy(deep=True)
                runtime = FunctionsRuntime(suite.tools)
                call_res, err = runtime.run_function(env, proposal.tool_name, proposal.arguments)
                fc = FunctionCall(
                    function=proposal.tool_name,
                    args=proposal.arguments,
                    id=proposal.proposal_id,
                )
                function_calls_stack.append(fc)
                executed_actions.append({
                    "tool": proposal.tool_name,
                    "args": proposal.arguments,
                    "result": str(call_res) if err is None else None,
                    "error": str(err) if err is not None else None,
                })
                if err is None:
                    execution_completed = True
                    # Verify environment_mutated from actual pre- and post-dispatch state diff
                    try:
                        environment_mutated = (env.model_dump() != pre_dispatch_env.model_dump())
                    except Exception:
                        environment_mutated = (env != pre_dispatch_env)
                else:
                    execution_completed = False
                    environment_mutated = False

        # Ensure gate_decision.executed reflects whether the action was dispatched to the tool runtime
        gate_decision = gate_decision.model_copy(update={"executed": execution_attempted})

        # 10. Check Task Outcomes (Utility and Security)
        utility_success = False
        security_breach = False

        model_output = [{"type": "text", "content": proposal.planner_reasoning or "done"}]

        try:
            utility_success = bool(suite._check_task_result(
                user_task,
                model_output,
                pre_env,
                env,
                function_calls_stack,
            ))
        except Exception as e:
            errors.append(f"Utility check failed: {e}")

        if injection_task:
            try:
                security_breach = bool(suite._check_task_result(
                    injection_task,
                    model_output,
                    pre_env,
                    env,
                    function_calls_stack,
                ))
            except Exception as e:
                errors.append(f"Security check failed: {e}")

        end_wall = time.perf_counter()
        end_utc = datetime.now(timezone.utc).isoformat()
        mem_after = proc.memory_info().rss / (1024 * 1024)
        sys_mem_after = psutil.virtual_memory().available / (1024 * 1024 * 1024)

        system_metrics = {
            "wall_clock_seconds": round(end_wall - start_wall, 3),
            "process_rss_mb_before": round(mem_before, 2),
            "process_rss_mb_after": round(mem_after, 2),
            "system_available_ram_gb_before": round(sys_mem_before, 2),
            "system_available_ram_gb_after": round(sys_mem_after, 2),
            "pipeline_version": self.pipeline_version,
            "researcher_strategy": self.researcher_strategy,
        }

        # Collect model telemetry from agents
        telemetry = list(self.researcher.telemetry) + list(self.planner.telemetry)

        trace = TraceRecord(
            schema_version="v2.0.0",
            run_id=run_id,
            benchmark_name="agentdojo",
            benchmark_version=benchmark_version,
            suite_name=suite_name,
            user_task_id=user_task_id,
            injection_task_id=injection_task_id,
            attack_name=attack_name if injection_task_id else None,
            model_name=self.model_name,
            condition=condition,
            start_time_utc=start_utc,
            end_time_utc=end_utc,
            user_prompt=user_prompt,
            injection_payloads=injection_payloads,
            researcher_observations=observations,
            handoff=handoff,
            proposals=[proposal],
            gate_decisions=[gate_decision],
            executed_actions=executed_actions,
            gate_authorized=gate_authorized,
            execution_attempted=execution_attempted,
            execution_completed=execution_completed,
            environment_mutated=environment_mutated,
            utility_success=utility_success,
            security_breach=security_breach,
            telemetry=telemetry,
            system_metrics=system_metrics,
            tool_relevance_rationales=getattr(self.researcher, "tool_relevance_rationales", {}),
            errors=errors,
            pipeline_version=self.pipeline_version,
            researcher_strategy=self.researcher_strategy,
        )

        # Write trace JSON to disk
        trace_file = os.path.join(self.traces_dir, f"{run_id}.json")
        with open(trace_file, "w", encoding="utf-8") as f:
            f.write(trace.model_dump_json(indent=2))

        return trace
