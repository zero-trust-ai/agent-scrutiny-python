"""
Tests for agent_scrutiny.plugins — base class and manager.

Covers:
    * Plugin base class: abstract enforcement, helper methods, default
      lifecycle hooks.
    * PluginManager: registration, initialization, parallel evaluation,
      error containment, shutdown.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    InteractionType,
    PluginVerdict,
)
from agent_scrutiny.plugins import Plugin, PluginManager


# ---------------------------------------------------------------------------
# Test fixtures — trivial plugins used throughout
# ---------------------------------------------------------------------------


class _AlwaysAllowPlugin(Plugin):
    @property
    def name(self) -> str:
        return "always-allow"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Always returns ALLOW."

    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        return self.allow(explanation="Always allowed.")


class _AlwaysBlockPlugin(Plugin):
    @property
    def name(self) -> str:
        return "always-block"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Always returns BLOCK."

    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        return self.block(
            explanation="Always blocked.",
            threats=["test_block"],
            confidence=0.99,
        )


class _AlwaysWarnPlugin(Plugin):
    @property
    def name(self) -> str:
        return "always-warn"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Always returns WARN."

    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        return self.warn(
            explanation="Always warned.",
            threats=["test_warn"],
            confidence=0.5,
        )


class _RaisesPlugin(Plugin):
    """Plugin that raises during evaluate. Used to test error containment."""

    @property
    def name(self) -> str:
        return "raises"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Raises in evaluate. For error-handling tests."

    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        raise RuntimeError("intentional test failure")


class _RequiresContextPlugin(Plugin):
    """Plugin that declares it needs the 'chain' context key."""

    @property
    def name(self) -> str:
        return "requires-context"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Demonstrates required_context()."

    def required_context(self) -> list[str]:
        return ["chain"]

    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        return self.allow()


class _LifecyclePlugin(Plugin):
    """Plugin that records its lifecycle calls. Used to test init/shutdown."""

    def __init__(self) -> None:
        self.initialized_with: dict[str, Any] | None = None
        self.shutdown_called = False

    @property
    def name(self) -> str:
        return "lifecycle"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Records lifecycle calls."

    async def initialize(self, config: dict[str, Any] | None = None) -> None:
        self.initialized_with = dict(config or {})

    async def shutdown(self) -> None:
        self.shutdown_called = True

    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        return self.allow()


class _InitFailsPlugin(Plugin):
    """Plugin whose initialize() raises. Used to test init error handling."""

    @property
    def name(self) -> str:
        return "init-fails"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Fails to initialize."

    async def initialize(self, config: dict[str, Any] | None = None) -> None:
        raise RuntimeError("initialization failed by design")

    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        # Should never be called, since initialize fails.
        return self.allow()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _interaction() -> AgentInteraction:
    return AgentInteraction(
        agent_input="hello",
        interaction_type=InteractionType.USER_TO_AGENT,
    )


def _context(**metadata: Any) -> EvaluationContext:
    return EvaluationContext(agent_id="test-agent", metadata=metadata)


# ---------------------------------------------------------------------------
# Plugin base class
# ---------------------------------------------------------------------------


class TestPluginBaseClass:
    def test_cannot_instantiate_abstract_plugin(self):
        """The abstract base class itself cannot be instantiated."""
        with pytest.raises(TypeError):
            Plugin()  # type: ignore[abstract]

    def test_subclass_must_implement_properties(self):
        """A subclass missing required properties cannot be instantiated."""

        class IncompletePlugin(Plugin):
            async def evaluate(self, interaction, context):
                return self.allow()

        with pytest.raises(TypeError):
            IncompletePlugin()  # type: ignore[abstract]

    def test_subclass_must_implement_evaluate(self):
        """A subclass missing evaluate cannot be instantiated."""

        class NoEvaluate(Plugin):
            @property
            def name(self) -> str:
                return "no-evaluate"

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def description(self) -> str:
                return "Missing evaluate."

        with pytest.raises(TypeError):
            NoEvaluate()  # type: ignore[abstract]

    def test_complete_subclass_instantiates(self):
        plugin = _AlwaysAllowPlugin()
        assert plugin.name == "always-allow"
        assert plugin.version == "1.0.0"

    def test_required_context_defaults_to_empty(self):
        """Plugins that do not override required_context() return []."""
        plugin = _AlwaysAllowPlugin()
        assert plugin.required_context() == []

    def test_required_context_override(self):
        plugin = _RequiresContextPlugin()
        assert plugin.required_context() == ["chain"]

    def test_repr_includes_name_and_version(self):
        plugin = _AlwaysAllowPlugin()
        r = repr(plugin)
        assert "always-allow" in r
        assert "1.0.0" in r


# ---------------------------------------------------------------------------
# Verdict helper methods
# ---------------------------------------------------------------------------


class TestVerdictHelpers:
    def test_allow_helper_fills_plugin_metadata(self):
        plugin = _AlwaysAllowPlugin()
        verdict = plugin.allow(explanation="OK")
        assert verdict.plugin_name == "always-allow"
        assert verdict.plugin_version == "1.0.0"
        assert verdict.decision == Decision.ALLOW
        assert verdict.threats == []
        assert verdict.explanation == "OK"
        assert verdict.evaluation_duration_ms == 0.0  # manager fills this in

    def test_block_helper_fills_plugin_metadata(self):
        plugin = _AlwaysAllowPlugin()
        verdict = plugin.block(
            explanation="bad", threats=["t1"], confidence=0.9
        )
        assert verdict.plugin_name == "always-allow"
        assert verdict.decision == Decision.BLOCK
        assert verdict.threats == ["t1"]
        assert verdict.confidence == 0.9

    def test_warn_helper_fills_plugin_metadata(self):
        plugin = _AlwaysAllowPlugin()
        verdict = plugin.warn(
            explanation="suspicious", threats=["t1"], confidence=0.5
        )
        assert verdict.plugin_name == "always-allow"
        assert verdict.decision == Decision.WARN
        assert verdict.threats == ["t1"]

    def test_allow_with_evidence(self):
        plugin = _AlwaysAllowPlugin()
        verdict = plugin.allow(
            explanation="OK", evidence={"checked_fields": ["a", "b"]}
        )
        assert verdict.evidence == {"checked_fields": ["a", "b"]}


# ---------------------------------------------------------------------------
# PluginManager — registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_one(self):
        manager = PluginManager()
        manager.register(_AlwaysAllowPlugin())
        assert len(manager.plugins) == 1
        assert manager.plugins[0].name == "always-allow"

    def test_register_many(self):
        manager = PluginManager()
        manager.register(_AlwaysAllowPlugin())
        manager.register(_AlwaysBlockPlugin())
        assert {p.name for p in manager.plugins} == {
            "always-allow",
            "always-block",
        }

    def test_duplicate_name_rejected(self):
        manager = PluginManager()
        manager.register(_AlwaysAllowPlugin())
        with pytest.raises(ValueError):
            manager.register(_AlwaysAllowPlugin())

    def test_plugins_property_is_snapshot(self):
        """Mutating the returned list does not affect the manager."""
        manager = PluginManager()
        manager.register(_AlwaysAllowPlugin())
        snapshot = manager.plugins
        snapshot.clear()
        assert len(manager.plugins) == 1


# ---------------------------------------------------------------------------
# PluginManager — initialization
# ---------------------------------------------------------------------------


class TestInitialization:
    @pytest.mark.asyncio
    async def test_initialize_all_calls_each_plugin(self):
        plugin = _LifecyclePlugin()
        manager = PluginManager()
        manager.register(plugin)
        await manager.initialize_all(configs={"lifecycle": {"key": "value"}})
        assert plugin.initialized_with == {"key": "value"}

    @pytest.mark.asyncio
    async def test_initialize_passes_empty_config_when_unspecified(self):
        plugin = _LifecyclePlugin()
        manager = PluginManager()
        manager.register(plugin)
        await manager.initialize_all()
        assert plugin.initialized_with == {}

    @pytest.mark.asyncio
    async def test_failing_plugin_disabled(self):
        """A plugin whose initialize() raises is disabled, not propagated."""
        bad = _InitFailsPlugin()
        good = _AlwaysAllowPlugin()
        manager = PluginManager()
        manager.register(bad)
        manager.register(good)
        await manager.initialize_all()
        # The good plugin is active; the bad one is not.
        active_names = {p.name for p in manager.active_plugins}
        assert "always-allow" in active_names
        assert "init-fails" not in active_names

    @pytest.mark.asyncio
    async def test_initialize_is_idempotent(self):
        """Calling initialize_all twice does not re-initialize plugins."""
        plugin = _LifecyclePlugin()
        manager = PluginManager()
        manager.register(plugin)
        await manager.initialize_all(configs={"lifecycle": {"k": 1}})
        await manager.initialize_all(configs={"lifecycle": {"k": 2}})
        # Second call did not run initialize again.
        assert plugin.initialized_with == {"k": 1}


# ---------------------------------------------------------------------------
# PluginManager — evaluation
# ---------------------------------------------------------------------------


class TestEvaluation:
    @pytest.mark.asyncio
    async def test_empty_manager_returns_empty_list(self):
        manager = PluginManager()
        verdicts = await manager.evaluate_all(_interaction(), _context())
        assert verdicts == []

    @pytest.mark.asyncio
    async def test_uninitialized_plugins_are_skipped(self):
        """Registered but uninitialized plugins do not run."""
        manager = PluginManager()
        manager.register(_AlwaysAllowPlugin())
        verdicts = await manager.evaluate_all(_interaction(), _context())
        assert verdicts == []

    @pytest.mark.asyncio
    async def test_active_plugins_produce_verdicts(self):
        manager = PluginManager()
        manager.register(_AlwaysAllowPlugin())
        manager.register(_AlwaysBlockPlugin())
        await manager.initialize_all()
        verdicts = await manager.evaluate_all(_interaction(), _context())
        assert len(verdicts) == 2
        decisions = {v.decision for v in verdicts}
        assert decisions == {Decision.ALLOW, Decision.BLOCK}

    @pytest.mark.asyncio
    async def test_duration_injected_by_manager(self):
        """Verdicts come back with non-zero evaluation_duration_ms."""
        manager = PluginManager()
        manager.register(_AlwaysAllowPlugin())
        await manager.initialize_all()
        verdicts = await manager.evaluate_all(_interaction(), _context())
        assert all(v.evaluation_duration_ms > 0.0 for v in verdicts)

    @pytest.mark.asyncio
    async def test_plugin_exception_becomes_block_verdict(self):
        """Exceptions in evaluate() are caught and become BLOCK verdicts."""
        manager = PluginManager()
        manager.register(_RaisesPlugin())
        await manager.initialize_all()
        verdicts = await manager.evaluate_all(_interaction(), _context())
        assert len(verdicts) == 1
        v = verdicts[0]
        assert v.decision == Decision.BLOCK
        assert v.plugin_name == "raises"
        assert "plugin_evaluation_error" in v.threats
        assert v.evidence is not None
        assert v.evidence["error_type"] == "RuntimeError"

    @pytest.mark.asyncio
    async def test_one_plugin_error_does_not_affect_others(self):
        """A failing plugin does not prevent other plugins from running."""
        manager = PluginManager()
        manager.register(_RaisesPlugin())
        manager.register(_AlwaysAllowPlugin())
        await manager.initialize_all()
        verdicts = await manager.evaluate_all(_interaction(), _context())
        assert len(verdicts) == 2
        # One BLOCK (from the failure) and one ALLOW (from the good plugin).
        decisions = {v.decision for v in verdicts}
        assert decisions == {Decision.BLOCK, Decision.ALLOW}

    @pytest.mark.asyncio
    async def test_missing_required_context_does_not_skip_plugin(self):
        """A plugin missing required_context still runs; warning is logged."""
        manager = PluginManager()
        manager.register(_RequiresContextPlugin())
        await manager.initialize_all()
        # 'chain' is missing from context.metadata.
        verdicts = await manager.evaluate_all(_interaction(), _context())
        # Plugin still runs and returns its verdict.
        assert len(verdicts) == 1
        assert verdicts[0].decision == Decision.ALLOW


# ---------------------------------------------------------------------------
# PluginManager — shutdown
# ---------------------------------------------------------------------------


class TestShutdown:
    @pytest.mark.asyncio
    async def test_shutdown_calls_each_initialized_plugin(self):
        plugin = _LifecyclePlugin()
        manager = PluginManager()
        manager.register(plugin)
        await manager.initialize_all()
        await manager.shutdown_all()
        assert plugin.shutdown_called is True

    @pytest.mark.asyncio
    async def test_shutdown_skips_uninitialized_plugins(self):
        """A registered-but-never-initialized plugin's shutdown is not called."""
        plugin = _LifecyclePlugin()
        manager = PluginManager()
        manager.register(plugin)
        # Did not call initialize_all.
        await manager.shutdown_all()
        assert plugin.shutdown_called is False
