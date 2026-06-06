"""
Tests for agent_scrutiny.models — the core data models.

These tests cover construction, validation, immutability, serialization
round-trips, and the convenience properties on SecurityVerdict.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    InteractionType,
    PluginVerdict,
    SecurityVerdict,
    Severity,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    """The string values matter for JSON serialization. Pin them."""

    def test_decision_values(self):
        assert Decision.ALLOW.value == "allow"
        assert Decision.WARN.value == "warn"
        assert Decision.BLOCK.value == "block"

    def test_interaction_type_values(self):
        assert InteractionType.USER_TO_AGENT.value == "user_to_agent"
        assert InteractionType.AGENT_TO_AGENT.value == "agent_to_agent"
        assert InteractionType.AGENT_TO_API.value == "agent_to_api"

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"


# ---------------------------------------------------------------------------
# AgentInteraction
# ---------------------------------------------------------------------------


class TestAgentInteraction:
    def test_minimal_construction(self):
        """Defaults populate when only required fields are given."""
        interaction = AgentInteraction(
            agent_input="hello",
            interaction_type=InteractionType.USER_TO_AGENT,
        )
        assert interaction.agent_input == "hello"
        assert interaction.agent_output is None
        assert interaction.interaction_id  # auto-generated UUID
        assert interaction.timestamp.tzinfo == timezone.utc

    def test_full_construction(self):
        """All fields populate cleanly when provided."""
        ts = datetime.now(timezone.utc)
        interaction = AgentInteraction(
            interaction_id="custom-id",
            agent_input="hello",
            agent_output="hi there",
            interaction_type=InteractionType.AGENT_TO_AGENT,
            timestamp=ts,
        )
        assert interaction.interaction_id == "custom-id"
        assert interaction.agent_output == "hi there"
        assert interaction.timestamp == ts

    def test_rejects_unknown_fields(self):
        """extra='forbid' catches typos and stale configs."""
        with pytest.raises(ValidationError):
            AgentInteraction(
                agent_input="hello",
                interaction_type=InteractionType.USER_TO_AGENT,
                unknown_field="oops",
            )

    def test_immutability(self):
        """Frozen models reject post-construction mutation."""
        interaction = AgentInteraction(
            agent_input="hello",
            interaction_type=InteractionType.USER_TO_AGENT,
        )
        with pytest.raises(ValidationError):
            interaction.agent_input = "changed"

    def test_unique_ids(self):
        """Auto-generated IDs are unique across instances."""
        a = AgentInteraction(
            agent_input="x", interaction_type=InteractionType.USER_TO_AGENT
        )
        b = AgentInteraction(
            agent_input="x", interaction_type=InteractionType.USER_TO_AGENT
        )
        assert a.interaction_id != b.interaction_id


# ---------------------------------------------------------------------------
# EvaluationContext
# ---------------------------------------------------------------------------


class TestEvaluationContext:
    def test_minimal_required_field(self):
        ctx = EvaluationContext(agent_id="agent-01")
        assert ctx.agent_id == "agent-01"
        assert ctx.user_id is None
        assert ctx.session_id is None
        assert ctx.metadata == {}

    def test_metadata_accepts_arbitrary_values(self):
        """metadata is the plugin escape hatch — open dict by design."""
        ctx = EvaluationContext(
            agent_id="agent-01",
            metadata={
                "chain": "ethereum",
                "value_eth": 10.5,
                "tags": ["high-value", "external"],
            },
        )
        assert ctx.metadata["chain"] == "ethereum"
        assert ctx.metadata["value_eth"] == 10.5
        assert ctx.metadata["tags"] == ["high-value", "external"]

    def test_requires_agent_id(self):
        with pytest.raises(ValidationError):
            EvaluationContext()  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# PluginVerdict
# ---------------------------------------------------------------------------


def _plugin_verdict(**overrides) -> PluginVerdict:
    """Factory helper — fills required fields with sensible defaults."""
    defaults = dict(
        plugin_name="test-plugin",
        plugin_version="1.0.0",
        decision=Decision.ALLOW,
        confidence=0.9,
        explanation="No threats detected.",
        evaluation_duration_ms=1.0,
    )
    defaults.update(overrides)
    return PluginVerdict(**defaults)


class TestPluginVerdict:
    def test_minimal_construction(self):
        verdict = _plugin_verdict()
        assert verdict.plugin_name == "test-plugin"
        assert verdict.threats == []
        assert verdict.evidence is None

    def test_confidence_at_boundaries(self):
        """Confidence accepts 0.0 and 1.0."""
        _plugin_verdict(confidence=0.0)
        _plugin_verdict(confidence=1.0)

    def test_confidence_above_one_rejected(self):
        with pytest.raises(ValidationError):
            _plugin_verdict(confidence=1.5)

    def test_confidence_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            _plugin_verdict(confidence=-0.1)

    def test_negative_duration_rejected(self):
        with pytest.raises(ValidationError):
            _plugin_verdict(evaluation_duration_ms=-1.0)

    def test_evidence_accepts_structured_data(self):
        verdict = _plugin_verdict(
            evidence={"matched_pattern": "ignore all previous", "line": 4},
        )
        assert verdict.evidence == {
            "matched_pattern": "ignore all previous",
            "line": 4,
        }

    def test_immutability(self):
        verdict = _plugin_verdict()
        with pytest.raises(ValidationError):
            verdict.confidence = 0.5


# ---------------------------------------------------------------------------
# SecurityVerdict
# ---------------------------------------------------------------------------


def _security_verdict(**overrides) -> SecurityVerdict:
    """Factory helper — fills required fields with sensible defaults."""
    defaults = dict(
        interaction_id="abc-123",
        decision=Decision.ALLOW,
        confidence=0.99,
        explanation="No threats detected.",
        evaluation_duration_ms=2.0,
    )
    defaults.update(overrides)
    return SecurityVerdict(**defaults)


class TestSecurityVerdict:
    def test_is_blocked_when_decision_is_block(self):
        verdict = _security_verdict(
            decision=Decision.BLOCK,
            explanation="Prompt injection detected.",
        )
        assert verdict.is_blocked is True
        assert verdict.is_safe is False

    def test_is_safe_when_decision_is_allow(self):
        verdict = _security_verdict(decision=Decision.ALLOW)
        assert verdict.is_blocked is False
        assert verdict.is_safe is True

    def test_warn_is_neither_blocked_nor_safe(self):
        """WARN means proceed-but-flag — explicitly not 'safe'."""
        verdict = _security_verdict(
            decision=Decision.WARN,
            explanation="Suspicious pattern; allowing with monitoring.",
        )
        assert verdict.is_blocked is False
        assert verdict.is_safe is False

    def test_has_threats_reflects_threat_list(self):
        empty = _security_verdict()
        assert empty.has_threats is False

        with_threats = _security_verdict(threats=["t1.1"])
        assert with_threats.has_threats is True

    def test_aggregates_plugin_verdicts(self):
        """SecurityVerdict can carry the contributing plugin verdicts."""
        plugin_v = _plugin_verdict(
            plugin_name="smart-contract-security",
            decision=Decision.BLOCK,
            confidence=0.95,
            threats=["reentrancy"],
            explanation="Recursive call before state update.",
            evaluation_duration_ms=2.4,
        )
        verdict = _security_verdict(
            decision=Decision.BLOCK,
            confidence=0.95,
            threats=["reentrancy"],
            explanation="Blocked: reentrancy in smart contract.",
            plugin_verdicts=[plugin_v],
        )
        assert len(verdict.plugin_verdicts) == 1
        assert verdict.plugin_verdicts[0].plugin_name == "smart-contract-security"


# ---------------------------------------------------------------------------
# Serialization round-trips
# ---------------------------------------------------------------------------


class TestSerialization:
    """
    JSON round-tripping matters for log shipping (structlog → SIEM) and for
    persisting audit records. Verify nothing gets lost.
    """

    def test_security_verdict_json_roundtrip(self):
        original = _security_verdict(
            decision=Decision.BLOCK,
            threats=["t1.1"],
            explanation="bad",
            plugin_verdicts=[
                _plugin_verdict(
                    decision=Decision.BLOCK,
                    threats=["t1.1"],
                    explanation="bad",
                ),
            ],
        )
        as_json = original.model_dump_json()
        restored = SecurityVerdict.model_validate_json(as_json)
        assert restored == original

    def test_agent_interaction_json_roundtrip(self):
        original = AgentInteraction(
            agent_input="hello",
            agent_output="hi",
            interaction_type=InteractionType.USER_TO_AGENT,
        )
        as_json = original.model_dump_json()
        restored = AgentInteraction.model_validate_json(as_json)
        assert restored == original

    def test_evaluation_context_json_roundtrip(self):
        original = EvaluationContext(
            agent_id="a-1",
            user_id="u-1",
            session_id="s-1",
            metadata={"k": "v", "n": 42},
        )
        as_json = original.model_dump_json()
        restored = EvaluationContext.model_validate_json(as_json)
        assert restored == original

    def test_decision_serializes_as_string(self):
        """Enum values must serialize as their string form for SIEM ingestion."""
        verdict = _security_verdict(decision=Decision.BLOCK)
        as_dict = verdict.model_dump(mode="json")
        assert as_dict["decision"] == "block"
