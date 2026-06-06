"""
Agent Scrutiny — Core: The Scrutinizer Class

The Scrutinizer is the central orchestrator. It receives an agent interaction,
runs it through the evaluation pipeline (input validation → core detection →
plugin evaluation → policy enforcement → output filtering → monitoring), and
returns a SecurityVerdict.

Stage 1 status: Input validation, core detection, policy enforcement, and
output filtering are still stubs. Plugin evaluation IS implemented — the
Scrutinizer accepts a list of plugins at construction and runs them through
the PluginManager on every evaluate() call, aggregating their verdicts into
the final SecurityVerdict.

References:
    Architecture     — docs/architecture.md
    Threat Model     — docs/threat-model.md
    Plugin Spec      — docs/plugins/plugin-specification.md
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any
from uuid import uuid4

import structlog

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    InteractionType,
    PluginVerdict,
    SecurityVerdict,
)
from agent_scrutiny.plugins import Plugin, PluginManager


# ---------------------------------------------------------------------------
# Mode — how strict the Scrutinizer is about acting on detected threats
# ---------------------------------------------------------------------------


class Mode(str, Enum):
    """
    How the Scrutinizer acts on detected threats.

    Members:
        STRICT:     Any detected threat results in a BLOCK verdict. Conservative
                    default appropriate for production.
        PERMISSIVE: Treated the same as STRICT in Stage 1. Will be refined to
                    block only on Severity.CRITICAL when Severity is integrated
                    into PluginVerdict.
        MONITOR:    No threat ever blocks. All verdicts pass through as ALLOW
                    with the threats and explanations preserved in the verdict
                    and the log. Appropriate for shadow-mode rollout.

    Mode is stored on the Scrutinizer at construction time and applied during
    verdict aggregation. It does not affect which plugins or detectors run —
    only how their verdicts are combined.
    """

    STRICT = "strict"
    PERMISSIVE = "permissive"
    MONITOR = "monitor"


# ---------------------------------------------------------------------------
# Scrutinizer — central orchestrator
# ---------------------------------------------------------------------------


class Scrutinizer:
    """
    The central security evaluation engine.

    A Scrutinizer instance is constructed once with its mode, policies, and
    plugins, then used to evaluate many interactions. Each evaluate() call is
    independent — the Scrutinizer itself is stateless across interactions.

    Stage 1 behavior:
        * Built-in detectors (input validation, core threat detection, output
          filtering) are not yet implemented and contribute no verdicts.
        * Registered plugins ARE run through the PluginManager on every
          evaluate() call, in parallel. Their verdicts are aggregated using
          a "most severe wins" rule, modulated by the configured Mode.

    Example:
        from agent_scrutiny import Scrutinizer, InteractionType
        from my_plugins import MyPlugin

        scrutinizer = Scrutinizer(
            mode="strict",
            plugins=[MyPlugin()],
        )
        await scrutinizer.initialize()

        verdict = await scrutinizer.evaluate_interaction(
            agent_input="What is my balance?",
            agent_id="support-agent-01",
        )

        if verdict.is_blocked:
            log.warning("blocked", reason=verdict.explanation)
    """

    def __init__(
        self,
        *,
        mode: Mode | str = Mode.STRICT,
        policies: list[str] | None = None,
        plugins: list[Plugin] | None = None,
    ) -> None:
        """
        Construct a Scrutinizer.

        Args:
            mode: How to act on detected threats. Default is STRICT. Accepts
                  a Mode enum or a string ("strict", "permissive", "monitor").
            policies: Optional list of policy identifiers. Stored for the
                      policy engine (not yet implemented).
            plugins: Optional list of plugins to register with the internal
                     PluginManager. Plugins must be initialized via the
                     async initialize() method before evaluation.

        Raises:
            ValueError: If `mode` is a string that does not match any Mode
                        value, or if any plugin names collide.
        """
        if isinstance(mode, str) and not isinstance(mode, Mode):
            mode = Mode(mode)

        self.mode: Mode = mode
        self.policies: list[str] = list(policies or [])
        self.scrutinizer_id: str = str(uuid4())

        self._plugin_manager = PluginManager()
        for plugin in plugins or []:
            self._plugin_manager.register(plugin)

        self._logger = structlog.get_logger(__name__).bind(
            scrutinizer_id=self.scrutinizer_id,
            mode=self.mode.value,
        )
        self._logger.info(
            "scrutinizer_initialized",
            policies=self.policies,
            plugin_count=len(self._plugin_manager.plugins),
        )

    def __repr__(self) -> str:
        return (
            f"Scrutinizer("
            f"mode={self.mode.value!r}, "
            f"policies={self.policies!r}, "
            f"plugin_count={len(self._plugin_manager.plugins)}, "
            f"scrutinizer_id={self.scrutinizer_id!r}"
            f")"
        )

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def initialize(
        self,
        plugin_configs: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """
        Initialize all registered plugins. Must be called once before
        evaluate(). Re-calling is a no-op for already-initialized plugins.

        Args:
            plugin_configs: Optional mapping of plugin_name -> config dict.
        """
        await self._plugin_manager.initialize_all(plugin_configs)
        self._logger.info(
            "scrutinizer_ready",
            active_plugin_count=len(self._plugin_manager.active_plugins),
        )

    async def shutdown(self) -> None:
        """Shut down all initialized plugins. Safe to call multiple times."""
        await self._plugin_manager.shutdown_all()
        self._logger.info("scrutinizer_shutdown")

    # -----------------------------------------------------------------------
    # Primary evaluation entry point
    # -----------------------------------------------------------------------

    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> SecurityVerdict:
        """
        Run the full evaluation pipeline for a single interaction.

        Stage 1: only plugin evaluation contributes verdicts. Built-in
        detectors land in subsequent steps.
        """
        eval_logger = self._logger.bind(
            interaction_id=interaction.interaction_id,
            agent_id=context.agent_id,
            interaction_type=interaction.interaction_type.value,
        )
        eval_logger.info("evaluation_started")

        start = time.perf_counter()

        # ----- TODO Stage 1+: built-in detectors land in subsequent steps ----
        # input_verdicts  = await self._input_validators.evaluate(...)
        # core_verdicts   = await self._core_detectors.evaluate(...)
        # output_verdicts = await self._output_filters.evaluate(...)
        # ---------------------------------------------------------------------

        # Run all active plugins in parallel through the PluginManager.
        plugin_verdicts = await self._plugin_manager.evaluate_all(
            interaction, context
        )

        # Aggregate.
        decision, confidence, threats, explanation = self._aggregate(
            plugin_verdicts
        )

        duration_ms = (time.perf_counter() - start) * 1000.0

        verdict = SecurityVerdict(
            interaction_id=interaction.interaction_id,
            decision=decision,
            confidence=confidence,
            threats=threats,
            explanation=explanation,
            plugin_verdicts=plugin_verdicts,
            evaluation_duration_ms=duration_ms,
        )

        eval_logger.info(
            "evaluation_completed",
            decision=verdict.decision.value,
            confidence=verdict.confidence,
            duration_ms=duration_ms,
            threat_count=len(verdict.threats),
            plugin_verdict_count=len(plugin_verdicts),
        )

        return verdict

    # -----------------------------------------------------------------------
    # Convenience entry point — accepts raw values, builds the models
    # -----------------------------------------------------------------------

    async def evaluate_interaction(
        self,
        agent_input: str,
        *,
        agent_id: str,
        agent_output: str | None = None,
        interaction_type: InteractionType = InteractionType.USER_TO_AGENT,
        user_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SecurityVerdict:
        """
        Convenience entry point that builds AgentInteraction and
        EvaluationContext from raw values, then delegates to evaluate().
        """
        interaction = AgentInteraction(
            agent_input=agent_input,
            agent_output=agent_output,
            interaction_type=interaction_type,
        )
        context = EvaluationContext(
            agent_id=agent_id,
            user_id=user_id,
            session_id=session_id,
            metadata=metadata or {},
        )
        return await self.evaluate(interaction, context)

    # -----------------------------------------------------------------------
    # Aggregation — combine plugin (and future detector) verdicts
    # -----------------------------------------------------------------------

    def _aggregate(
        self,
        plugin_verdicts: list[PluginVerdict],
    ) -> tuple[Decision, float, list[str], str]:
        """
        Combine plugin verdicts into a final (decision, confidence, threats,
        explanation) tuple. "Most severe wins," modulated by Mode.

        Stage 1: only plugin verdicts contribute. Built-in detector verdicts
        will be added to the inputs of this method in subsequent steps.
        """
        if not plugin_verdicts:
            return (
                Decision.ALLOW,
                1.0,
                [],
                (
                    "No plugins or detectors are active. "
                    "Verdict is unconditional ALLOW. "
                    "(Stage 1 built-in detectors not yet implemented.)"
                ),
            )

        # Collect every threat, deduplicated, preserving first-seen order.
        all_threats: list[str] = []
        seen: set[str] = set()
        for v in plugin_verdicts:
            for t in v.threats:
                if t not in seen:
                    seen.add(t)
                    all_threats.append(t)

        has_block = any(v.decision == Decision.BLOCK for v in plugin_verdicts)
        has_warn = any(v.decision == Decision.WARN for v in plugin_verdicts)

        # MONITOR mode never blocks, regardless of plugin verdicts.
        # PERMISSIVE is treated as STRICT in Stage 1; will refine once
        # Severity flows through PluginVerdict.
        if self.mode == Mode.MONITOR:
            final_decision = Decision.ALLOW
        elif has_block:
            final_decision = Decision.BLOCK
        elif has_warn:
            final_decision = Decision.WARN
        else:
            final_decision = Decision.ALLOW

        # Confidence: max from verdicts that match the final decision.
        # Falls back to overall max for MONITOR-suppressed blocks.
        matching = [v for v in plugin_verdicts if v.decision == final_decision]
        if matching:
            confidence = max(v.confidence for v in matching)
        else:
            confidence = max(v.confidence for v in plugin_verdicts)

        explanation = self._build_explanation(
            final_decision, plugin_verdicts, mode=self.mode
        )
        return final_decision, confidence, all_threats, explanation

    @staticmethod
    def _build_explanation(
        decision: Decision,
        plugin_verdicts: list[PluginVerdict],
        *,
        mode: Mode,
    ) -> str:
        """Render a human-readable explanation from contributing verdicts."""
        blockers = [
            v.plugin_name for v in plugin_verdicts if v.decision == Decision.BLOCK
        ]
        warners = [
            v.plugin_name for v in plugin_verdicts if v.decision == Decision.WARN
        ]

        if mode == Mode.MONITOR and (blockers or warners):
            flagging = sorted(set(blockers + warners))
            return (
                f"MONITOR mode: threats flagged by "
                f"{', '.join(flagging)}, but not blocking."
            )

        if decision == Decision.BLOCK:
            return f"Blocked by: {', '.join(sorted(set(blockers)))}."
        if decision == Decision.WARN:
            return f"Flagged by: {', '.join(sorted(set(warners)))}."
        return "No threats detected across all active plugins."
