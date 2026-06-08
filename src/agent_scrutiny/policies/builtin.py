"""
Agent Scrutiny — Built-in Policies

A small library of generally-useful policies that ship with the SDK.

These cover the most common operator scenarios for Stage 1:

    * ThresholdPolicy             — adjust decisions based on confidence
    * RequireMultipleThreatsPolicy — require multi-signal confirmation
    * ThreatCategoryPolicy         — force a decision for specific threat patterns
    * AgentAllowlistPolicy         — cap severity for trusted agents

Each is a thin, testable class. Operators compose them in a list, in the
order they want them applied. Custom policies sit alongside built-ins
without ceremony — same Policy base class, same interface.
"""

from __future__ import annotations

import re

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    SecurityVerdict,
)
from agent_scrutiny.policies.base import Policy

# Severity ordering for AgentAllowlistPolicy's cap logic.
_SEVERITY: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.WARN: 1,
    Decision.BLOCK: 2,
}


# ---------------------------------------------------------------------------
# ThresholdPolicy
# ---------------------------------------------------------------------------


class ThresholdPolicy(Policy):
    """
    Adjust the verdict's decision based on confidence thresholds.

    Two independent configurations:

        * ``downgrade_block_below``: if the verdict is BLOCK and confidence
          is strictly below this value, downgrade to WARN.
        * ``upgrade_warn_above``: if the verdict is WARN and confidence is
          at or above this value, upgrade to BLOCK.

    Either or both may be set. If neither is configured, the policy is a
    no-op (and ``ValueError`` is raised at construction time to flag the
    likely mistake).

    Use case: cautious rollout of new detectors. A new detector with
    moderate confidence shouldn't fully block traffic — start with WARN
    everywhere and upgrade only when confidence proves out, OR start with
    BLOCK on high-confidence matches only and let lower-confidence matches
    flow through as WARN.

    Example:
        ThresholdPolicy(downgrade_block_below=0.7)
        # Any BLOCK with confidence < 0.7 becomes WARN.

        ThresholdPolicy(upgrade_warn_above=0.85)
        # Any WARN with confidence >= 0.85 becomes BLOCK.
    """

    def __init__(
        self,
        *,
        downgrade_block_below: float | None = None,
        upgrade_warn_above: float | None = None,
        name: str = "threshold-policy",
    ) -> None:
        super().__init__()
        if downgrade_block_below is None and upgrade_warn_above is None:
            raise ValueError(
                "ThresholdPolicy must configure at least one of "
                "downgrade_block_below or upgrade_warn_above."
            )
        for label, value in (
            ("downgrade_block_below", downgrade_block_below),
            ("upgrade_warn_above", upgrade_warn_above),
        ):
            if value is not None and not 0.0 <= value <= 1.0:
                raise ValueError(f"{label} must be in [0.0, 1.0], got {value}")

        self._downgrade_block_below = downgrade_block_below
        self._upgrade_warn_above = upgrade_warn_above
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    async def apply(
        self,
        verdict: SecurityVerdict,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> SecurityVerdict:
        if (
            self._downgrade_block_below is not None
            and verdict.decision == Decision.BLOCK
            and verdict.confidence < self._downgrade_block_below
        ):
            return self._set_decision(
                verdict,
                Decision.WARN,
                reason=(
                    f"confidence {verdict.confidence:.3f} < "
                    f"{self._downgrade_block_below}"
                ),
            )

        if (
            self._upgrade_warn_above is not None
            and verdict.decision == Decision.WARN
            and verdict.confidence >= self._upgrade_warn_above
        ):
            return self._set_decision(
                verdict,
                Decision.BLOCK,
                reason=(
                    f"confidence {verdict.confidence:.3f} >= "
                    f"{self._upgrade_warn_above}"
                ),
            )

        return verdict


# ---------------------------------------------------------------------------
# RequireMultipleThreatsPolicy
# ---------------------------------------------------------------------------


class RequireMultipleThreatsPolicy(Policy):
    """
    Downgrade BLOCK to WARN unless at least N distinct threat IDs are present.

    Use case: reduce single-detector false positives. A single detector
    saying BLOCK might be wrong — a single pattern firing, a single
    threshold tripping. Two independent detectors both saying BLOCK is a
    much stronger signal.

    This policy does not affect WARN or ALLOW verdicts.

    Example:
        RequireMultipleThreatsPolicy(minimum_threats=2)
        # BLOCK with a single threat → downgrades to WARN
        # BLOCK with two or more threats → stays BLOCK
    """

    def __init__(
        self,
        *,
        minimum_threats: int = 2,
        name: str = "require-multiple-threats",
    ) -> None:
        super().__init__()
        if minimum_threats < 1:
            raise ValueError("minimum_threats must be >= 1")
        self._minimum_threats = minimum_threats
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    async def apply(
        self,
        verdict: SecurityVerdict,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> SecurityVerdict:
        if verdict.decision != Decision.BLOCK:
            return verdict
        if len(verdict.threats) >= self._minimum_threats:
            return verdict
        return self._set_decision(
            verdict,
            Decision.WARN,
            reason=(
                f"{len(verdict.threats)} threat(s) present, "
                f"need at least {self._minimum_threats} to BLOCK"
            ),
        )


# ---------------------------------------------------------------------------
# ThreatCategoryPolicy
# ---------------------------------------------------------------------------


class ThreatCategoryPolicy(Policy):
    """
    Force a specific decision when any threat ID matches a regex pattern.

    Use case: ops rules that override detector defaults for whole threat
    categories. For example, in a regulated context, "any
    ``data_exfiltration.*`` threat must be BLOCK, regardless of what the
    detector decided" — even if the detector returned WARN.

    Can be used to either *upgrade* (WARN→BLOCK) or *downgrade* (BLOCK→
    WARN) based on threat category. The policy sets the decision to
    whatever ``decision`` was configured, irrespective of direction.

    The pattern is a Python regex matched against each threat ID. Use
    ``r"data_exfiltration\\..*"`` to match the family, or
    ``r"data_exfiltration\\.us_ssn"`` to match exactly one.

    Example:
        ThreatCategoryPolicy(
            threat_pattern=r"data_exfiltration\\..*",
            decision=Decision.BLOCK,
        )
        # Any verdict whose threats include a data_exfiltration.* entry
        # is forced to BLOCK.
    """

    def __init__(
        self,
        *,
        threat_pattern: str,
        decision: Decision,
        name: str = "threat-category-policy",
    ) -> None:
        super().__init__()
        try:
            self._compiled = re.compile(threat_pattern)
        except re.error as exc:
            raise ValueError(
                f"Invalid threat_pattern regex {threat_pattern!r}: {exc}"
            ) from exc
        self._threat_pattern_str = threat_pattern
        self._target_decision = decision
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    async def apply(
        self,
        verdict: SecurityVerdict,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> SecurityVerdict:
        matched = [t for t in verdict.threats if self._compiled.match(t)]
        if not matched:
            return verdict
        if verdict.decision == self._target_decision:
            return verdict
        return self._set_decision(
            verdict,
            self._target_decision,
            reason=(
                f"threat(s) {matched} match {self._threat_pattern_str!r}, "
                f"forcing {self._target_decision.value.upper()}"
            ),
        )


# ---------------------------------------------------------------------------
# AgentAllowlistPolicy
# ---------------------------------------------------------------------------


class AgentAllowlistPolicy(Policy):
    """
    Cap verdict severity for allowlisted agents.

    Agents in the allowlist have their verdicts capped at ``max_decision``
    (either WARN or ALLOW). Non-allowlisted agents pass through unchanged.

    The cap is a one-way operation — this policy never UPGRADES severity.
    A BLOCK becomes WARN (or ALLOW) for an allowlisted agent; an ALLOW
    stays ALLOW; a WARN stays WARN or becomes ALLOW depending on the cap.

    Use case: high-trust internal agents during testing, agents operating
    under separate review processes, or shadow-mode rollout for specific
    agents while others stay enforced.

    ``max_decision=BLOCK`` is rejected at construction because it would
    make the policy a no-op (and that's almost certainly a mistake).

    Example:
        AgentAllowlistPolicy(
            allowlisted_agents={"trusted-agent-01", "trusted-agent-02"},
            max_decision=Decision.WARN,
        )
    """

    def __init__(
        self,
        *,
        allowlisted_agents: set[str] | list[str],
        max_decision: Decision = Decision.WARN,
        name: str = "agent-allowlist",
    ) -> None:
        super().__init__()
        if max_decision == Decision.BLOCK:
            raise ValueError(
                "AgentAllowlistPolicy max_decision must be WARN or ALLOW; "
                "BLOCK would make the policy a no-op."
            )
        self._agents: frozenset[str] = frozenset(allowlisted_agents)
        self._max_decision = max_decision
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    async def applies_to(
        self,
        verdict: SecurityVerdict,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> bool:
        return context.agent_id in self._agents

    async def apply(
        self,
        verdict: SecurityVerdict,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> SecurityVerdict:
        # Only downgrade — never upgrade.
        if _SEVERITY[verdict.decision] <= _SEVERITY[self._max_decision]:
            return verdict
        return self._set_decision(
            verdict,
            self._max_decision,
            reason=f"agent {context.agent_id!r} is allowlisted",
        )