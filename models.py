"""
Agent Scrutiny — Core Data Models

This module defines the fundamental data models that flow through the
Scrutinizer evaluation pipeline. Every detector, plugin, policy, and monitor
speaks these contracts.

The models are intentionally minimal at Stage 1. Additional fields and
specialized verdict types will be added as the pipeline grows in later stages.

References:
    Architecture     — docs/architecture.md
    Threat Model     — docs/threat-model.md (canonical T1.x–T4.x taxonomy)
    Plugin Spec      — docs/plugins/plugin-specification.md

Conventions:
    * All models are Pydantic v2.
    * All models are frozen — verdicts and interactions are immutable after
      creation. Augmentation is done via model_copy(update={...}).
    * Unknown fields are rejected (extra="forbid") to catch typos and config
      errors early.
    * Timestamps are timezone-aware UTC.
    * Identifiers are opaque strings (UUID4 by default).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums — foundational vocabulary
# ---------------------------------------------------------------------------


class Decision(str, Enum):
    """
    The decision an evaluator (detector, plugin, or the Scrutinizer itself)
    can reach about an agent interaction.

    Values are lowercase strings to keep JSON serialization clean.

    Members:
        ALLOW: The interaction is safe to proceed.
        WARN:  Allow the interaction, but flag it for monitoring or review.
        BLOCK: Reject the interaction. It must not proceed.
    """

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class InteractionType(str, Enum):
    """
    The kind of agent interaction being evaluated. Drives policy selection
    and threat-model relevance.

    Members:
        USER_TO_AGENT:  A human user interacting with an agent.
        AGENT_TO_AGENT: One agent sending a message to another agent (A2A/MCP).
        AGENT_TO_API:   An agent calling an external API or tool.
    """

    USER_TO_AGENT = "user_to_agent"
    AGENT_TO_AGENT = "agent_to_agent"
    AGENT_TO_API = "agent_to_api"


class Severity(str, Enum):
    """
    Severity rating from the threat model. Mirrors the scale defined in
    docs/threat-model.md.

    Members:
        CRITICAL: Can lead to data breach, unauthorized action, or system
                  compromise.
        HIGH:     Degrades security posture or enables further attacks.
        MEDIUM:   Reduces trust or causes incorrect behavior without direct
                  data exposure.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


# ---------------------------------------------------------------------------
# Shared base — common Pydantic config for every Scrutiny model
# ---------------------------------------------------------------------------


class _ScrutinyBaseModel(BaseModel):
    """
    Internal base class with shared model configuration.

    Every Agent Scrutiny model inherits this. The defaults are intentionally
    strict:

        * extra="forbid"  — unknown fields raise ValidationError. This catches
                            typos and stale configs early.
        * frozen=True     — instances are immutable after construction.
                            Use model_copy(update={...}) to augment.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )


# ---------------------------------------------------------------------------
# Factories — default value helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def _new_id() -> str:
    """Return a new opaque identifier (UUID4 as string)."""
    return str(uuid4())


# ---------------------------------------------------------------------------
# Inputs — the things being evaluated
# ---------------------------------------------------------------------------


class AgentInteraction(_ScrutinyBaseModel):
    """
    A single agent interaction to be evaluated by the Scrutinizer.

    The ``agent_output`` field is optional. Pre-output evaluations (input-only)
    set it to None; in those cases the Scrutinizer evaluates only the
    input-side of the pipeline.

    Stage 1 supports text-only inputs and outputs. Structured payloads (dict)
    are planned for Stage 2.

    Example:
        interaction = AgentInteraction(
            agent_input="What is my account balance?",
            interaction_type=InteractionType.USER_TO_AGENT,
        )
    """

    interaction_id: str = Field(
        default_factory=_new_id,
        description=(
            "Unique identifier for this interaction. "
            "Auto-generated as a UUID4 if not provided. "
            "Used to correlate logs and audit records across the pipeline."
        ),
    )

    agent_input: str = Field(
        description=(
            "The input sent to the agent. "
            "Stage 1 supports text only; structured input is planned for Stage 2."
        ),
    )

    agent_output: str | None = Field(
        default=None,
        description=(
            "The agent's response, if available. "
            "None indicates a pre-output (input-only) evaluation."
        ),
    )

    interaction_type: InteractionType = Field(
        description=(
            "What kind of interaction this is. "
            "Used by the Scrutinizer to select applicable policies."
        ),
    )

    timestamp: datetime = Field(
        default_factory=_utcnow,
        description="When the interaction occurred. Timezone-aware UTC.",
    )


class EvaluationContext(_ScrutinyBaseModel):
    """
    Metadata accompanying an AgentInteraction.

    Plugins declare what context keys they require via ``required_context()``.
    The Scrutinizer logs a warning if those keys are missing; evaluation still
    proceeds, but plugins that strictly require context should handle the
    missing-key case themselves.

    The ``metadata`` field is an open dictionary for plugin-specific context —
    chain ID for smart-contract plugins, patient ID for healthcare plugins,
    transaction amount for financial plugins, etc.

    Example:
        context = EvaluationContext(
            agent_id="customer-support-01",
            user_id="user-12345",
            session_id="session-abc",
            metadata={"plan_tier": "premium", "region": "us-east"},
        )
    """

    agent_id: str = Field(
        description="Identifier for the agent being evaluated. Required.",
    )

    user_id: str | None = Field(
        default=None,
        description="Identifier for the end user, if applicable.",
    )

    session_id: str | None = Field(
        default=None,
        description="Identifier for the session this interaction belongs to.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Free-form context used by plugins. "
            "Keys are plugin-specific; document them in each plugin's "
            "required_context() return value."
        ),
    )


# ---------------------------------------------------------------------------
# Outputs — verdicts from plugins and the Scrutinizer
# ---------------------------------------------------------------------------


class PluginVerdict(_ScrutinyBaseModel):
    """
    The verdict returned by a single plugin's ``evaluate()`` call.

    Multiple PluginVerdict instances are aggregated by the Scrutinizer into
    a final SecurityVerdict. Aggregation rule is "most severe wins":

        * Any BLOCK → final SecurityVerdict is BLOCK.
        * Any WARN (and no BLOCK) → final is WARN.
        * All ALLOW → final is ALLOW.

    Example:
        return PluginVerdict(
            plugin_name="smart-contract-security",
            plugin_version="1.2.0",
            decision=Decision.BLOCK,
            confidence=0.95,
            threats=["reentrancy"],
            explanation="Recursive call detected in withdraw() before state update.",
            evaluation_duration_ms=2.4,
        )
    """

    plugin_name: str = Field(
        description="The plugin's unique identifier (from Plugin.name()).",
    )

    plugin_version: str = Field(
        description="Semantic version of the plugin that produced this verdict.",
    )

    decision: Decision = Field(
        description="This plugin's recommendation for the interaction.",
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Confidence in the decision, on [0.0, 1.0]. "
            "1.0 = certain, 0.0 = guessing. Plugins should be conservative — "
            "report low confidence rather than inflate it."
        ),
    )

    threats: list[str] = Field(
        default_factory=list,
        description=(
            "Threat IDs detected by this plugin, e.g. "
            "'prompt_injection.direct_override' or 'reentrancy'. "
            "Empty list means no threats were found."
        ),
    )

    explanation: str = Field(
        description=(
            "Human-readable explanation of the verdict. "
            "Required by the Explainable Security principle — a verdict "
            "without an explanation is not actionable."
        ),
    )

    evidence: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional structured evidence supporting the verdict. "
            "Plugin-specific schema; used for debugging and audit. "
            "Must be JSON-serializable."
        ),
    )

    evaluation_duration_ms: float = Field(
        ge=0.0,
        description=(
            "How long this plugin's evaluation took, in milliseconds. "
            "Used for performance monitoring and budget enforcement."
        ),
    )


class SecurityVerdict(_ScrutinyBaseModel):
    """
    The final verdict produced by the Scrutinizer for a single agent
    interaction.

    Aggregates the results of input validation, core threat detection,
    plugin evaluation, policy enforcement, and output filtering into a
    single decision with a human-readable explanation.

    Aggregation rule: "most severe wins."

        * If any contributing verdict is BLOCK → SecurityVerdict is BLOCK.
        * If any is WARN (and none BLOCK)      → SecurityVerdict is WARN.
        * Otherwise                            → SecurityVerdict is ALLOW.

    Example:
        verdict = SecurityVerdict(
            interaction_id=interaction.interaction_id,
            decision=Decision.BLOCK,
            confidence=0.97,
            threats=["prompt_injection.direct_override"],
            explanation="Input contains known injection override pattern.",
            plugin_verdicts=[],
            evaluation_duration_ms=4.2,
        )

        if verdict.is_blocked:
            log.warning("blocked", verdict=verdict.model_dump())
    """

    interaction_id: str = Field(
        description="The ID of the interaction this verdict applies to.",
    )

    decision: Decision = Field(
        description="The Scrutinizer's final decision for the interaction.",
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Aggregate confidence in the final decision.",
    )

    threats: list[str] = Field(
        default_factory=list,
        description=(
            "All threat IDs detected across the entire evaluation pipeline. "
            "Deduplicated from contributing verdicts."
        ),
    )

    explanation: str = Field(
        description=(
            "Human-readable explanation of the final verdict, combining all "
            "contributing factors. Always populated, never empty."
        ),
    )

    plugin_verdicts: list[PluginVerdict] = Field(
        default_factory=list,
        description=(
            "Individual verdicts from each plugin that participated in "
            "evaluation. Preserved for audit and debugging."
        ),
    )

    evaluation_duration_ms: float = Field(
        ge=0.0,
        description="Total time spent evaluating this interaction, in milliseconds.",
    )

    timestamp: datetime = Field(
        default_factory=_utcnow,
        description="When the verdict was issued. Timezone-aware UTC.",
    )

    # -----------------------------------------------------------------------
    # Convenience properties — keep the API ergonomic for common checks.
    # -----------------------------------------------------------------------

    @property
    def is_blocked(self) -> bool:
        """True iff the decision is BLOCK. The most common check at call sites."""
        return self.decision == Decision.BLOCK

    @property
    def is_safe(self) -> bool:
        """
        True iff the decision is ALLOW.

        Note: WARN is *not* considered safe by this property. WARN means
        "proceed but flag" — code that needs full safety should check this,
        not just ``not is_blocked``.
        """
        return self.decision == Decision.ALLOW

    @property
    def has_threats(self) -> bool:
        """True iff at least one threat was detected, regardless of decision."""
        return bool(self.threats)
