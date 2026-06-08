"""
Agent Scrutiny — Policy Engine

The PolicyEngine runs registered policies in sequence over a SecurityVerdict.
Each policy can transform the verdict; the next policy sees the result of
the previous one.

Order matters. Policies registered earlier run earlier. Operators are
responsible for ordering policies sensibly (e.g., specific overrides before
generic thresholds), the engine itself does not impose any ordering
semantics.

Error containment: if a policy's ``apply()`` raises, the engine fails closed
by forcing the verdict to BLOCK with an error annotation. This is symmetric
with the PluginManager's behavior — a misbehaving policy cannot silently
suppress security decisions.
"""

from __future__ import annotations

import structlog

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    SecurityVerdict,
)
from agent_scrutiny.policies.base import Policy


class PolicyEngine:
    """
    Sequential evaluator for security policies.

    Typical usage (the Scrutinizer manages this internally):

        engine = PolicyEngine([
            ThreatCategoryPolicy(
                threat_pattern=r"data_exfiltration\\..*",
                decision=Decision.BLOCK,
            ),
            ThresholdPolicy(downgrade_block_below=0.7),
        ])

        final_verdict = await engine.apply_all(raw_verdict, interaction, context)
    """

    def __init__(self, policies: list[Policy] | None = None) -> None:
        self._policies: list[Policy] = list(policies or [])
        self._logger = structlog.get_logger(__name__)

        # Reject duplicate names — operators get clearer errors than
        # discovering at runtime that two policies share a name.
        seen: set[str] = set()
        for p in self._policies:
            if p.name in seen:
                raise ValueError(
                    f"Duplicate policy name {p.name!r} in policy list."
                )
            seen.add(p.name)

    @property
    def policies(self) -> list[Policy]:
        """Read-only snapshot of registered policies, in evaluation order."""
        return list(self._policies)

    def register(self, policy: Policy) -> None:
        """Append a policy. Raises ValueError on a duplicate name."""
        if any(p.name == policy.name for p in self._policies):
            raise ValueError(
                f"A policy named {policy.name!r} is already registered."
            )
        self._policies.append(policy)
        self._logger.info("policy_registered", policy_name=policy.name)

    # -----------------------------------------------------------------------
    # Evaluation
    # -----------------------------------------------------------------------

    async def apply_all(
        self,
        verdict: SecurityVerdict,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> SecurityVerdict:
        """
        Run every registered policy over the verdict in order. Each policy
        sees the transformed verdict from the previous policy.

        Policies whose ``applies_to()`` returns False are skipped. Policies
        that raise during ``apply()`` fail closed — the verdict's decision
        becomes BLOCK with the error preserved in the explanation and an
        error threat appended.

        Returns the verdict after all policies have run.
        """
        current = verdict

        for policy in self._policies:
            try:
                if not await policy.applies_to(current, interaction, context):
                    continue
            except Exception as exc:
                self._logger.error(
                    "policy_applies_to_failed",
                    policy_name=policy.name,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
                current = self._fail_closed(current, policy.name, exc)
                continue

            try:
                current = await policy.apply(current, interaction, context)
            except Exception as exc:
                self._logger.error(
                    "policy_apply_failed",
                    policy_name=policy.name,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
                current = self._fail_closed(current, policy.name, exc)

        return current

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _fail_closed(
        verdict: SecurityVerdict,
        policy_name: str,
        exc: Exception,
    ) -> SecurityVerdict:
        """
        Build a fail-closed verdict when a policy raises. Forces BLOCK,
        annotates the explanation, and appends a policy-error threat.
        """
        error_threat = f"policy.{policy_name}.evaluation_error"
        new_threats = list(verdict.threats)
        if error_threat not in new_threats:
            new_threats.append(error_threat)

        return verdict.model_copy(
            update={
                "decision": Decision.BLOCK,
                "explanation": (
                    f"{verdict.explanation} "
                    f"[Policy {policy_name!r} failed: "
                    f"{type(exc).__name__}; failing closed.]"
                ),
                "threats": new_threats,
            }
        )