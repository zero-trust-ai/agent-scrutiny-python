"""
Agent Scrutiny — Policy Base Class

Policies transform SecurityVerdicts. They run AFTER plugin/detector
aggregation but BEFORE Mode is applied, so policies see the raw "what the
detectors found" state and decide whether to amplify, soften, or override
it based on rules that operators configure.

This is the configuration-as-code half of the security framework — detectors
say what's in the data; policies say what to do about it. Examples:

    * "Downgrade BLOCK to WARN when confidence < 0.7" (cautious rollout)
    * "Require at least 2 distinct threats to BLOCK" (multi-signal)
    * "All data_exfiltration.* threats must BLOCK" (regulated context)
    * "Agents in this allowlist cap at WARN" (trusted internal agents)

Stage 1 forward-compatibility note:
    The (verdict, interaction, context) signature accommodates both Stage 1
    rules (which only read fields already present on these objects) and
    Stage 2 authorization rules (which will read identity/resource fields
    added to EvaluationContext later). Stage 1 policies do not need to
    change when those fields arrive.

References:
    Architecture — docs/architecture.md (Policy Enforcement phase)
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    SecurityVerdict,
)


class Policy(ABC):
    """
    Abstract base class for security policies.

    A conforming policy implements:
        * One property: ``name`` — short identifier (kebab-case).
        * One coroutine: ``apply(verdict, interaction, context)`` returning
          a (possibly transformed) SecurityVerdict.

    May optionally override:
        * ``applies_to(verdict, interaction, context)`` — returns False to
          skip this policy for a given evaluation. Default is always True.

    Example:
        class HighConfidenceOnly(Policy):
            @property
            def name(self) -> str:
                return "high-confidence-only"

            async def apply(self, verdict, interaction, context):
                if verdict.decision == Decision.BLOCK and verdict.confidence < 0.8:
                    return self._set_decision(
                        verdict, Decision.WARN,
                        reason=f"confidence {verdict.confidence} < 0.8",
                    )
                return verdict
    """

    # -----------------------------------------------------------------------
    # Required contract
    # -----------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this policy (kebab-case)."""
        ...

    @abstractmethod
    async def apply(
        self,
        verdict: SecurityVerdict,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> SecurityVerdict:
        """
        Transform the verdict. Return unchanged if no transformation needed.

        Implementations should use the ``_set_decision`` helper when they
        change the decision, so audit annotations are consistent across
        policies.

        Implementations may raise. The PolicyEngine catches exceptions and
        fails closed — the verdict's decision becomes BLOCK with the error
        preserved.
        """
        ...

    # -----------------------------------------------------------------------
    # Optional contract — overrideable with a sensible default
    # -----------------------------------------------------------------------

    async def applies_to(
        self,
        verdict: SecurityVerdict,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> bool:
        """
        Return False to skip this policy for the given evaluation.

        Useful for policies that are only relevant under certain conditions
        (e.g., AgentAllowlistPolicy only applies when the agent_id is in
        its allowlist). The default implementation always returns True.

        Separating ``applies_to`` from ``apply`` keeps the "is this
        relevant?" check separate from the "what does it do?" logic.
        """
        return True

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _set_decision(
        self,
        verdict: SecurityVerdict,
        new_decision: Decision,
        *,
        reason: str | None = None,
        added_threats: list[str] | None = None,
    ) -> SecurityVerdict:
        """
        Return a copy of ``verdict`` with the decision changed and an
        audit annotation appended to the explanation.

        Args:
            verdict: The verdict being transformed.
            new_decision: The new decision to set.
            reason: Optional human-readable reason for the transformation.
                    Gets appended to the explanation as
                    ``[Policy 'name': reason]``.
            added_threats: Optional list of additional threat IDs to add to
                           the verdict's threats list (deduplicated, order
                           preserved).
        """
        new_explanation = verdict.explanation
        if reason:
            new_explanation = (
                f"{verdict.explanation} [Policy '{self.name}': {reason}]"
            )

        update: dict = {
            "decision": new_decision,
            "explanation": new_explanation,
        }

        if added_threats:
            seen = set(verdict.threats)
            new_threats = list(verdict.threats)
            for t in added_threats:
                if t not in seen:
                    seen.add(t)
                    new_threats.append(t)
            update["threats"] = new_threats

        return verdict.model_copy(update=update)

    def __repr__(self) -> str:
        try:
            return f"{type(self).__name__}(name={self.name!r})"
        except NotImplementedError:
            return f"{type(self).__name__}(<uninstantiable>)"