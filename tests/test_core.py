"""
Tests for agent_scrutiny.core — the Scrutinizer class.

Updated for Stage 1 step 3 — covers construction, mode handling, both
evaluate entry points, lifecycle (initialize/shutdown), and the plugin
aggregation logic.
"""

from __future__ import annotations

import pytest

from agent_scrutiny.core import Mode, Scrutinizer
from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    InteractionType,
    PluginVerdict,
    SecurityVerdict,
)
from agent_scrutiny.plugins import Plugin


# ---------------------------------------------------------------------------
# Test plugins
# ---------------------------------------------------------------------------


class _AllowPlugin(Plugin):
    @property
    def name(self) -> str:
        return "allow-plugin"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Always ALLOW."

    async def evaluate(self, interaction, context) -> PluginVerdict:
        return self.allow()


class _BlockPlugin(Plugin):
    @property
    def name(self) -> str:
        return "block-plugin"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Always BLOCK."

    async def evaluate(self, interaction, context) -> PluginVerdict:
        return self.block(
            explanation="Blocked by test plugin.",
            threats=["test_block"],
            confidence=0.95,
        )


class _WarnPlugin(Plugin):
    @property
    def name(self) -> str:
        return "warn-plugin"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Always WARN."

    async def evaluate(self, interaction, context) -> PluginVerdict:
        return self.warn(
            explanation="Flagged by test plugin.",
            threats=["test_warn"],
            confidence=0.6,
        )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_default_construction(self):
        s = Scrutinizer()
        assert s.mode == Mode.STRICT
        assert s.policies == []
        assert s.scrutinizer_id

    def test_unique_scrutinizer_ids(self):
        a = Scrutinizer()
        b = Scrutinizer()
        assert a.scrutinizer_id != b.scrutinizer_id

    def test_custom_mode_enum(self):
        s = Scrutinizer(mode=Mode.PERMISSIVE)
        assert s.mode == Mode.PERMISSIVE

    def test_mode_from_string(self):
        s = Scrutinizer(mode="monitor")
        assert s.mode == Mode.MONITOR

    def test_invalid_mode_string_raises(self):
        with pytest.raises(ValueError):
            Scrutinizer(mode="not-a-mode")

    def test_policies_stored(self):
        s = Scrutinizer(policies=["a", "b"])
        assert s.policies == ["a", "b"]

    def test_plugins_registered_at_construction(self):
        plugin = _AllowPlugin()
        s = Scrutinizer(plugins=[plugin])
        # No public accessor for the internal manager; the repr exposes the count.
        assert "plugin_count=1" in repr(s)

    def test_duplicate_plugin_names_rejected_at_construction(self):
        """Two plugins with the same name should not both register."""
        with pytest.raises(ValueError):
            Scrutinizer(plugins=[_AllowPlugin(), _AllowPlugin()])


# ---------------------------------------------------------------------------
# evaluate() — no plugins (stub path)
# ---------------------------------------------------------------------------


class TestEvaluateNoPlugins:
    @pytest.fixture
    def scrutinizer(self) -> Scrutinizer:
        return Scrutinizer()

    @pytest.fixture
    def interaction(self) -> AgentInteraction:
        return AgentInteraction(
            agent_input="hello",
            interaction_type=InteractionType.USER_TO_AGENT,
        )

    @pytest.fixture
    def context(self) -> EvaluationContext:
        return EvaluationContext(agent_id="test-agent")

    @pytest.mark.asyncio
    async def test_returns_security_verdict(
        self, scrutinizer, interaction, context
    ):
        verdict = await scrutinizer.evaluate(interaction, context)
        assert isinstance(verdict, SecurityVerdict)

    @pytest.mark.asyncio
    async def test_no_plugins_returns_allow(
        self, scrutinizer, interaction, context
    ):
        """With no plugins or detectors, evaluation returns ALLOW."""
        verdict = await scrutinizer.evaluate(interaction, context)
        assert verdict.decision == Decision.ALLOW
        assert verdict.threats == []
        assert verdict.plugin_verdicts == []

    @pytest.mark.asyncio
    async def test_explanation_mentions_stub_state(
        self, scrutinizer, interaction, context
    ):
        verdict = await scrutinizer.evaluate(interaction, context)
        # The default explanation should make the "nothing active" state visible.
        assert verdict.explanation
        assert "no plugins" in verdict.explanation.lower() or "stage 1" in verdict.explanation.lower()

    @pytest.mark.asyncio
    async def test_duration_is_measured(
        self, scrutinizer, interaction, context
    ):
        verdict = await scrutinizer.evaluate(interaction, context)
        assert verdict.evaluation_duration_ms >= 0.0
        assert verdict.evaluation_duration_ms < 1000.0


# ---------------------------------------------------------------------------
# evaluate() — with plugins (aggregation)
# ---------------------------------------------------------------------------


class TestEvaluateWithPlugins:
    @pytest.mark.asyncio
    async def test_single_allow_plugin_produces_allow(self):
        s = Scrutinizer(plugins=[_AllowPlugin()])
        await s.initialize()
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        assert verdict.decision == Decision.ALLOW
        assert verdict.is_safe is True
        assert len(verdict.plugin_verdicts) == 1

    @pytest.mark.asyncio
    async def test_single_block_plugin_produces_block(self):
        s = Scrutinizer(plugins=[_BlockPlugin()])
        await s.initialize()
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        assert verdict.decision == Decision.BLOCK
        assert verdict.is_blocked is True
        assert "test_block" in verdict.threats

    @pytest.mark.asyncio
    async def test_any_block_overrides_allow(self):
        """Most severe wins: BLOCK + ALLOW → BLOCK."""
        s = Scrutinizer(plugins=[_AllowPlugin(), _BlockPlugin()])
        await s.initialize()
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        assert verdict.decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_warn_only_produces_warn(self):
        """WARN + ALLOW (no BLOCK) → WARN."""
        s = Scrutinizer(plugins=[_AllowPlugin(), _WarnPlugin()])
        await s.initialize()
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        assert verdict.decision == Decision.WARN
        assert verdict.is_safe is False
        assert verdict.is_blocked is False
        assert "test_warn" in verdict.threats

    @pytest.mark.asyncio
    async def test_block_dominates_warn(self):
        """BLOCK + WARN → BLOCK (most severe wins)."""
        s = Scrutinizer(plugins=[_WarnPlugin(), _BlockPlugin()])
        await s.initialize()
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        assert verdict.decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_threats_aggregated_and_deduped(self):
        """All threats from all plugins are collected, deduplicated."""

        class DupPlugin(Plugin):
            @property
            def name(self) -> str:
                return "dup"

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def description(self) -> str:
                return "Reports same threat."

            async def evaluate(self, interaction, context):
                return self.block(
                    explanation="dup", threats=["test_block"], confidence=0.9
                )

        # Two plugins both report "test_block" → it should appear once.
        s = Scrutinizer(plugins=[_BlockPlugin(), DupPlugin()])
        await s.initialize()
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        assert verdict.threats == ["test_block"]

    @pytest.mark.asyncio
    async def test_plugin_verdicts_preserved_on_security_verdict(self):
        """The contributing PluginVerdicts must survive into the final verdict."""
        s = Scrutinizer(plugins=[_AllowPlugin(), _BlockPlugin()])
        await s.initialize()
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        assert len(verdict.plugin_verdicts) == 2
        names = {v.plugin_name for v in verdict.plugin_verdicts}
        assert names == {"allow-plugin", "block-plugin"}


# ---------------------------------------------------------------------------
# Mode behavior
# ---------------------------------------------------------------------------


class TestModes:
    @pytest.mark.asyncio
    async def test_strict_mode_blocks_on_block_verdict(self):
        s = Scrutinizer(mode=Mode.STRICT, plugins=[_BlockPlugin()])
        await s.initialize()
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        assert verdict.decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_monitor_mode_never_blocks(self):
        """MONITOR mode always returns ALLOW even when plugins say BLOCK."""
        s = Scrutinizer(mode=Mode.MONITOR, plugins=[_BlockPlugin()])
        await s.initialize()
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        assert verdict.decision == Decision.ALLOW
        # But threats are still preserved in the verdict.
        assert "test_block" in verdict.threats
        # And the underlying plugin verdict still says BLOCK.
        assert verdict.plugin_verdicts[0].decision == Decision.BLOCK

    @pytest.mark.asyncio
    async def test_monitor_mode_explanation_mentions_monitor(self):
        s = Scrutinizer(mode=Mode.MONITOR, plugins=[_BlockPlugin()])
        await s.initialize()
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        assert "monitor" in verdict.explanation.lower()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_initialize_and_shutdown(self):
        """Lifecycle methods complete without error on default Scrutinizer."""
        s = Scrutinizer(plugins=[_AllowPlugin()])
        await s.initialize()
        await s.shutdown()

    @pytest.mark.asyncio
    async def test_evaluate_works_without_explicit_initialize(self):
        """
        Calling evaluate() without initialize() returns ALLOW because no
        plugins are active. This is a sharp edge — log evidence is the
        signal that plugins are not running.
        """
        s = Scrutinizer(plugins=[_BlockPlugin()])
        verdict = await s.evaluate_interaction(
            agent_input="hello", agent_id="test-agent"
        )
        # BlockPlugin is registered but not initialized, so it does not run.
        assert verdict.decision == Decision.ALLOW
        assert verdict.plugin_verdicts == []
