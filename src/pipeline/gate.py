"""Deterministic Action Authorization Boundary outside the LLM reasoning loop."""

import uuid
from typing import Any, Dict, List, Optional, Set
from src.pipeline.schema import (
    ActionProposal,
    AuthorizationResult,
    EvaluationMode,
    GateDecision,
    TrustLevel,
)
from src.pipeline.provenance import ProvenanceTracker

# Critical control parameters: determine action target, destination, recipient, or code execution
CRITICAL_CONTROL_PARAMS: Set[str] = {
    "recipient",
    "recipients",
    "to",
    "email",
    "destination_iban",
    "account_number",
    "iban",
    "url",
    "file_path",
    "path",
    "command",
    "target",
    "file_id",
    "event_id",
    "participants",
}

# Content payload parameters: carry informational payload to an authorized destination
CONTENT_PAYLOAD_PARAMS: Set[str] = {
    "body",
    "subject",
    "message",
    "content",
    "text",
    "description",
    "notes",
    "summary",
    "comment",
}


class DeterministicAuthorizationBoundary:
    """Independent reference monitor enforcing tool permissions, argument validation, and provenance policies."""

    def __init__(self, policy_version: str = "v2.0.0"):
        self.policy_version = policy_version

    def evaluate(
        self,
        proposal: ActionProposal,
        user_goal: str,
        allowed_tools: Set[str],
        condition: EvaluationMode,
        provenance_tracker: Optional[ProvenanceTracker] = None,
    ) -> AuthorizationResult:
        """Evaluate an action proposal against the specified condition policy.
        
        Evaluates:
        1. Tool authorization (Is tool permitted by policy whitelist?)
        2. Argument validation (Are arguments syntactically valid?)
        3. Argument provenance (Are control parameters tainted or unverified?)
        """
        decision_id = f"gate-{uuid.uuid4().hex[:12]}"
        
        # --- Mode 1: BASELINE (No enforcement) ---
        if condition == EvaluationMode.BASELINE:
            is_actionable = proposal.tool_name not in ("none", "", None)
            return AuthorizationResult(
                decision_id=decision_id,
                policy_version=self.policy_version,
                mode=condition,
                decision=GateDecision.ALLOW,
                reason="Baseline condition: no authorization boundary active (direct pass-through).",
                evaluated_tool=proposal.tool_name,
                evaluated_arguments=proposal.arguments,
                blocked_arguments=[],
                gate_authorized=True,
                executed=is_actionable,
            )

        # --- Check 0: Informational / No-op Proposal ---
        if proposal.tool_name in ("none", "", None):
            return AuthorizationResult(
                decision_id=decision_id,
                policy_version=self.policy_version,
                mode=condition,
                decision=GateDecision.ALLOW,
                reason="Informational proposal: no state-changing tool call requested.",
                evaluated_tool="none",
                evaluated_arguments={},
                blocked_arguments=[],
                gate_authorized=True,
                executed=False,
            )

        # --- Check 1: Tool Whitelist (Applies to CONVENTIONAL & PROVENANCE_AWARE) ---
        if proposal.tool_name not in allowed_tools:
            return AuthorizationResult(
                decision_id=decision_id,
                policy_version=self.policy_version,
                mode=condition,
                decision=GateDecision.DENY_UNAUTHORIZED_TOOL,
                reason=f"Tool '{proposal.tool_name}' is not in the authorized tool whitelist for this task: {sorted(list(allowed_tools))}",
                evaluated_tool=proposal.tool_name,
                evaluated_arguments=proposal.arguments,
                blocked_arguments=list(proposal.arguments.keys()),
                gate_authorized=False,
                executed=False,
            )

        # --- Check 2: Schema & Non-Empty Validation ---
        if not isinstance(proposal.arguments, dict):
            return AuthorizationResult(
                decision_id=decision_id,
                policy_version=self.policy_version,
                mode=condition,
                decision=GateDecision.DENY_SCHEMA_VIOLATION,
                reason=f"Arguments for tool '{proposal.tool_name}' must be a dictionary, got {type(proposal.arguments)}",
                evaluated_tool=proposal.tool_name,
                evaluated_arguments={},
                blocked_arguments=[],
                gate_authorized=False,
                executed=False,
            )

        # --- Mode 2: CONVENTIONAL AUTHORIZATION (Blind to argument provenance) ---
        if condition == EvaluationMode.CONVENTIONAL:
            return AuthorizationResult(
                decision_id=decision_id,
                policy_version=self.policy_version,
                mode=condition,
                decision=GateDecision.ALLOW,
                reason=f"Conventional authorization passed: Tool '{proposal.tool_name}' is whitelisted and arguments conform to schema.",
                evaluated_tool=proposal.tool_name,
                evaluated_arguments=proposal.arguments,
                blocked_arguments=[],
                gate_authorized=True,
                executed=True,
            )

        # --- Mode 3: PROVENANCE-AWARE AUTHORIZATION ---
        # Inspect argument provenance against untrusted observations vs. user goal.
        # Partition into critical control parameters vs content payload parameters.
        blocked_args = []
        taint_reasons = []

        for arg_key, arg_val in proposal.arguments.items():
            arg_key_lower = arg_key.lower()
            arg_trust = proposal.argument_provenance.get(arg_key, TrustLevel.TRUSTED)
            taint_source = proposal.taint_matches.get(arg_key)

            is_control = arg_key_lower in CRITICAL_CONTROL_PARAMS
            is_content = arg_key_lower in CONTENT_PAYLOAD_PARAMS

            # Rule A: Critical control parameter derived from untrusted observation
            if is_control and arg_trust == TrustLevel.DERIVED_TAINTED:
                blocked_args.append(arg_key)
                taint_reasons.append(
                    f"Critical control argument '{arg_key}' contains tainted entity derived from untrusted observation '{taint_source}' and not authorized in user goal"
                )

            # Rule B: Critical control parameter with unverified / uncertain provenance
            elif is_control and arg_trust == TrustLevel.UNCERTAIN:
                blocked_args.append(arg_key)
                taint_reasons.append(
                    f"Critical control argument '{arg_key}' with value '{arg_val}' has unverified provenance (not found in user goal or trusted claims)"
                )

            # Rule C: Content payload parameters
            # Allowed to carry tainted or untrusted information to authorized destinations
            elif is_content:
                # Content payload allowed even if derived from untrusted observation,
                # provided routing control parameters are safe.
                pass

            # Unknown argument type: apply conservative check if tainted
            elif arg_trust == TrustLevel.DERIVED_TAINTED:
                blocked_args.append(arg_key)
                taint_reasons.append(
                    f"Argument '{arg_key}' is tainted by untrusted source '{taint_source}'"
                )

        if blocked_args:
            return AuthorizationResult(
                decision_id=decision_id,
                policy_version=self.policy_version,
                mode=condition,
                decision=GateDecision.DENY_TAINTED_ARGUMENT,
                reason=f"Provenance gate violation: {'; '.join(taint_reasons)}",
                evaluated_tool=proposal.tool_name,
                evaluated_arguments=proposal.arguments,
                blocked_arguments=blocked_args,
                gate_authorized=False,
                executed=False,
            )

        # All checks passed
        return AuthorizationResult(
            decision_id=decision_id,
            policy_version=self.policy_version,
            mode=condition,
            decision=GateDecision.ALLOW,
            reason=f"Provenance-aware authorization passed: Tool '{proposal.tool_name}' and all control parameters verified against user policy.",
            evaluated_tool=proposal.tool_name,
            evaluated_arguments=proposal.arguments,
            blocked_arguments=[],
            gate_authorized=True,
            executed=True,
        )
