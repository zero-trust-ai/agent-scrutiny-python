"""
Agent Scrutiny — Core: The Scrutinizer Class

The Scrutinizer is the central orchestrator. It receives an agent interaction,
runs it through the evaluation pipeline (plugin/detector evaluation → raw
verdict aggregation → policy transformation → mode application), and returns
a SecurityVerdict.

Stage 1 pipeline (this step completes it):
    1. Run all registered plugins in parallel (PluginManager).
    2. Aggregate their verdicts into a raw SecurityVerdict via
       "most severe wins."
    3. Apply every registered policy in order (PolicyEngine). Policies can
       transform the raw verdict — downgrade, upgrade, or annotate.
    4. Apply Mode behavior. MONITOR forces ALLOW on the final decision
       while preserving threats and plugin_verdicts for audit visibility.
       STRICT and PERMISSIVE pass through (PERMISSIVE refinement is Stage 2).

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
from agent_scrutiny.policies import Policy, PolicyEngine


# ---------------------------------------------------------------------------
# Mode — how strict the Scrutinizer is about acting on detected threats
# ---------------------------------------------------------------------------


class Mode(str, Enum):
    """
    How the Scrutinizer acts on detected threats.

    Members:
        STRICT:     Any detected threat results in a BLOCK verdict (after
                    policies have run). Conservative default appropriate
                    for production.
        PERMISSIVE: Treated the same as STRICT in Stage 1. Will be refined
                    to block only on Severity.CRITICAL when Severity is
                    integrated into PluginVerdict.
        MONITOR:    No threat ever blocks the final verdict. All decisions
                    pass through as ALLOW with the threats, plugin_verdicts,
                    and policy annotations preserved. Appropriate for
                    shadow-mode rollout.

    Mode is applied LAST in the pipeline, after policies have run. This
    means policies see the underlying decision state, not a mode-masked
    version, and MONITOR still suppresses everything to ALLOW for the
    final verdict regardless of what policies decided.
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

    Stage 1 pipeline (now complete):
        Plugins run in parallel → raw verdict via "most severe wins" →
        policies transform the raw verdict in sequence → Mode applied last.

    Example:
        from agent_scrutiny import (
            Scrutinizer, PromptInjectionDetector, DataExfiltrationDetector,
            ThresholdPolicy, ThreatCategoryPolicy, Decision,
        )

        scrutinizer = Scrutinizer(
            mode="strict",
            plugins=[
                PromptInjectionDetector(),
                DataExfiltrationDetector(),
            ],
            policies=[
                ThreatCategoryPolicy(
                    threat_pattern=r"data_exfiltration\\..*",
                    decision=Decision.BLOCK,
                ),
                ThresholdPolicy(downgrade_block_below=0.7),
            ],
        )
        await scrutinizer.initialize()

        verdict = await scrutinizer.evaluate_interaction(
            agent_input="What is my balance?",
            agent_id="support-agent-01",
        )
    """

    def __init__(
        self,
        *,
        mode: Mode | str = Mode.STRICT,
        policies: list[Policy] | None = None,
        plugins: list[Plugin] | None = None,
    ) -> None:
        """
        Construct a Scrutinizer.

        Args:
            mode: How to act on detected threats. Default is STRICT. Accepts
                  a Mode enum or a string ("strict", "permissive", "monitor").
            policies: Optional list of Policy instances. Applied in order
                      after plugin aggregation, before Mode is applied.
            plugins: Optional list of plugins. Must be initialized via the
                     async initialize() method before evaluation.

        Raises:
            ValueError: If `mode` is a string that does not match any Mode
                        value, or if any plugin or policy names collide.
        """
        if isinstance(mode, str) and not isinstance(mode, Mode):
            mode = Mode(mode)

        self.mode: Mode = mode
        self.scrutinizer_id: str = str(uuid4())

        self._plugin_manager = PluginManager()
        for plugin in plugins or []:
            self._plugin_manager.register(plugin)

        self._policy_engine = PolicyEngine(policies or [])

        self._logger = structlog.get_logger(__name__).bind(
            scrutinizer_id=self.scrutinizer_id,
            mode=self.mode.value,
        )
        self._logger.info(
            "scrutinizer_initialized",
            plugin_count=len(self._plugin_manager.plugins),
            policy_count=len(self._policy_engine.policies),
            policy_names=[p.name for p in self._policy_engine.policies],
        )

    def __repr__(self) -> str:
        return (
            f"Scrutinizer("
            f"mode={self.mode.value!r}, "
            f"plugin_count={len(self._plugin_manager.plugins)}, "
            f"policy_count={len(self._policy_engine.policies)}, "
            f"scrutinizer_id={self.scrutinizer_id!r}"
            f")"
        )

    @property
    def policies(self) -> list[Policy]:
        """Read-only snapshot of registered policies, in evaluation order."""
        return self._policy_engine.policies

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
        Run the full evaluation pipeline for a single interaction:
        plugins → raw verdict → policies → mode.
        """
        eval_logger = self._logger.bind(
            interaction_id=interaction.interaction_id,
            agent_id=context.agent_id,
            interaction_type=interaction.interaction_type.value,
        )
        eval_logger.info("evaluation_started")

        start = time.perf_counter()

        # 1. Run all active plugins in parallel.
        plugin_verdicts = await self._plugin_manager.evaluate_all(
            interaction, context
        )

        # 2. Build raw verdict from plugin verdicts ("most severe wins").
        raw_verdict = self._build_raw_verdict(interaction, plugin_verdicts)

        # 3. Apply policies in sequence.
        policy_verdict = await self._policy_engine.apply_all(
            raw_verdict, interaction, context
        )

        # 4. Apply Mode behavior to produce the final verdict.
        final_verdict = self._apply_mode(policy_verdict)

        # 5. Stamp duration last.
        duration_ms = (time.perf_counter() - start) * 1000.0
        final_verdict = final_verdict.model_copy(
            update={"evaluation_duration_ms": duration_ms}
        )

        eval_logger.info(
            "evaluation_completed",
            decision=final_verdict.decision.value,
            confidence=final_verdict.confidence,
            duration_ms=duration_ms,
            threat_count=len(final_verdict.threats),
            plugin_verdict_count=len(plugin_verdicts),
            policy_count=len(self._policy_engine.policies),
        )

        return final_verdict

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
        """Convenience: build models from raw values, then delegate to evaluate()."""
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
    # Pipeline stages
    # -----------------------------------------------------------------------

    def _build_raw_verdict(
        self,
        interaction: AgentInteraction,
        plugin_verdicts: list[PluginVerdict],
    ) -> SecurityVerdict:
        """
        Aggregate plugin verdicts into a raw SecurityVerdict via "most
        severe wins." Does NOT apply mode — that happens in _apply_mode
        after policies have run.
        """
        if not plugin_verdicts:
            return SecurityVerdict(
                interaction_id=interaction.interaction_id,
                decision=Decision.ALLOW,
                confidence=1.0,
                threats=[],
                explanation=(
                    "No plugins or detectors are active. "
                    "Verdict is unconditional ALLOW."
                ),
                plugin_verdicts=[],
                evaluation_duration_ms=0.0,
            )

        # Collect and deduplicate threats, preserving first-seen order.
        all_threats: list[str] = []
        seen: set[str] = set()
        for v in plugin_verdicts:
            for t in v.threats:
                if t not in seen:
                    seen.add(t)
                    all_threats.append(t)

        has_block = any(v.decision == Decision.BLOCK for v in plugin_verdicts)
        has_warn = any(v.decision == Decision.WARN for v in plugin_verdicts)

        if has_block:
            decision = Decision.BLOCK
        elif has_warn:
            decision = Decision.WARN
        else:
            decision = Decision.ALLOW

        matching = [v for v in plugin_verdicts if v.decision == decision]
        if matching:
            confidence = max(v.confidence for v in matching)
        else:
            confidence = max(v.confidence for v in plugin_verdicts)

        return SecurityVerdict(
            interaction_id=interaction.interaction_id,
            decision=decision,
            confidence=confidence,
            threats=all_threats,
            explanation=self._build_explanation(decision, plugin_verdicts),
            plugin_verdicts=plugin_verdicts,
            evaluation_duration_ms=0.0,
        )

    def _apply_mode(self, verdict: SecurityVerdict) -> SecurityVerdict:
        """
        Apply Mode semantics. MONITOR forces ALLOW while preserving threats
        and plugin_verdicts (and any policy annotations) for audit.
        STRICT/PERMISSIVE pass through unchanged.
        """
        if self.mode != Mode.MONITOR:
            return verdict
        if verdict.decision == Decision.ALLOW:
            return verdict
        return verdict.model_copy(
            update={
                "decision": Decision.ALLOW,
                "explanation": (
                    f"{verdict.explanation} [MONITOR mode: not blocking.]"
                ),
            }
        )

    @staticmethod
    def _build_explanation(
        decision: Decision,
        plugin_verdicts: list[PluginVerdict],
    ) -> str:
        """Render a human-readable explanation from the aggregated decision."""
        if decision == Decision.BLOCK:
            blockers = sorted(
                {v.plugin_name for v in plugin_verdicts if v.decision == Decision.BLOCK}
            )
            return f"Blocked by: {', '.join(blockers)}."
        if decision == Decision.WARN:
            warners = sorted(
                {v.plugin_name for v in plugin_verdicts if v.decision == Decision.WARN}
            )
            return f"Flagged by: {', '.join(warners)}."
        return "No threats detected across all active plugins."