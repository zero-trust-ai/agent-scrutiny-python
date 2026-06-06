"""
Agent Scrutiny — Plugin Manager

The PluginManager owns the lifecycle of every registered plugin and dispatches
evaluations. It is the boundary between the Scrutinizer core and untrusted
plugin code: a misbehaving plugin cannot crash the manager or affect other
plugins.

Responsibilities:
    * Register plugins by name (rejects duplicates).
    * Call initialize() on every plugin once, before evaluations start.
      Plugins that fail to initialize are disabled — they are not called
      during evaluate_all().
    * Dispatch evaluate() to every active plugin in parallel via
      asyncio.gather. Measure timing externally and inject it into each
      verdict via model_copy (PluginVerdict is frozen).
    * Convert plugin exceptions to BLOCK verdicts so a faulty plugin
      fails closed rather than crashing the pipeline.
    * Call shutdown() on every plugin during teardown, swallowing errors so
      one plugin's misbehavior cannot prevent others from cleaning up.

Stage 1 scope: explicit registration only. Plugin discovery (registry,
plugin.yaml) lands in Stage 2.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    PluginVerdict,
)
from agent_scrutiny.plugins.base import Plugin


class PluginManager:
    """
    Lifecycle and dispatch coordinator for plugins.

    Typical usage (the Scrutinizer manages this internally):

        manager = PluginManager()
        manager.register(MyPlugin())
        manager.register(OtherPlugin())
        await manager.initialize_all()

        verdicts = await manager.evaluate_all(interaction, context)
        # ... aggregate verdicts ...

        await manager.shutdown_all()
    """

    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}
        self._initialized: set[str] = set()
        self._disabled: set[str] = set()
        self._logger = structlog.get_logger(__name__)

    # -----------------------------------------------------------------------
    # Registration
    # -----------------------------------------------------------------------

    def register(self, plugin: Plugin) -> None:
        """
        Register a plugin by its name.

        Raises:
            ValueError: If a plugin with the same name is already registered.
                        Names must be globally unique within a manager.
        """
        if plugin.name in self._plugins:
            raise ValueError(
                f"A plugin named {plugin.name!r} is already registered."
            )
        self._plugins[plugin.name] = plugin
        self._logger.info(
            "plugin_registered",
            plugin_name=plugin.name,
            plugin_version=plugin.version,
        )

    @property
    def plugins(self) -> list[Plugin]:
        """Read-only snapshot of all registered plugins."""
        return list(self._plugins.values())

    @property
    def active_plugins(self) -> list[Plugin]:
        """Plugins that were initialized successfully and are not disabled."""
        return [
            p
            for name, p in self._plugins.items()
            if name in self._initialized and name not in self._disabled
        ]

    # -----------------------------------------------------------------------
    # Lifecycle: initialize
    # -----------------------------------------------------------------------

    async def initialize_all(
        self,
        configs: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """
        Initialize every registered plugin.

        Args:
            configs: Optional mapping of plugin_name -> config dict. Plugins
                     whose names are absent from the mapping receive an
                     empty config.

        Plugins that raise during initialize() are disabled for subsequent
        evaluations. Their failures are logged but do not prevent other
        plugins from initializing.
        """
        configs = configs or {}
        for name, plugin in self._plugins.items():
            if name in self._initialized:
                continue
            plugin_config = configs.get(name, {})
            try:
                await plugin.initialize(plugin_config)
                self._initialized.add(name)
                self._logger.info("plugin_initialized", plugin_name=name)
            except Exception as exc:
                self._disabled.add(name)
                self._logger.error(
                    "plugin_initialization_failed",
                    plugin_name=name,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )

    # -----------------------------------------------------------------------
    # Lifecycle: evaluate
    # -----------------------------------------------------------------------

    async def evaluate_all(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> list[PluginVerdict]:
        """
        Run every active plugin's evaluate() in parallel and return their
        verdicts.

        Active means "successfully initialized and not disabled." Plugins
        that have not been initialized, or that failed initialization, are
        skipped.

        Each verdict's evaluation_duration_ms is measured externally and
        injected via model_copy — plugin authors do not need to time
        themselves.

        Exceptions raised by a plugin's evaluate() are caught and converted
        to a BLOCK verdict with the error preserved in the evidence field.
        This implements "fail closed" — a broken plugin should not silently
        let bad traffic through.

        Args:
            interaction: The interaction to evaluate.
            context: The accompanying context.

        Returns:
            A list of PluginVerdicts, one per active plugin. Order is not
            guaranteed (results return in completion order); the Scrutinizer
            re-sorts as needed for aggregation.
        """
        active = self.active_plugins
        if not active:
            return []

        # Warn about plugins whose required_context keys are missing.
        # The plugin still runs — required_context is advisory.
        for plugin in active:
            missing = [
                key
                for key in plugin.required_context()
                if key not in context.metadata
            ]
            if missing:
                self._logger.warning(
                    "plugin_missing_required_context",
                    plugin_name=plugin.name,
                    missing_keys=missing,
                )

        # Run all active plugins in parallel.
        coros = [
            self._evaluate_one(plugin, interaction, context)
            for plugin in active
        ]
        verdicts = await asyncio.gather(*coros)
        return list(verdicts)

    async def _evaluate_one(
        self,
        plugin: Plugin,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        """
        Run a single plugin, measure timing, and convert exceptions to
        BLOCK verdicts. PluginVerdict is frozen, so timing is injected via
        model_copy after the fact.
        """
        start = time.perf_counter()
        try:
            verdict = await plugin.evaluate(interaction, context)
        except Exception as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            self._logger.error(
                "plugin_evaluation_failed",
                plugin_name=plugin.name,
                interaction_id=interaction.interaction_id,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            # Fail closed: a broken plugin produces a BLOCK verdict so the
            # request does not silently pass through unexamined.
            return PluginVerdict(
                plugin_name=plugin.name,
                plugin_version=plugin.version,
                decision=Decision.BLOCK,
                confidence=1.0,
                threats=["plugin_evaluation_error"],
                explanation=(
                    f"Plugin {plugin.name!r} raised "
                    f"{type(exc).__name__}: {exc}. Failing closed."
                ),
                evidence={
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
                evaluation_duration_ms=duration_ms,
            )

        duration_ms = (time.perf_counter() - start) * 1000.0
        # PluginVerdict is frozen — inject the measured duration via copy.
        return verdict.model_copy(
            update={"evaluation_duration_ms": duration_ms}
        )

    # -----------------------------------------------------------------------
    # Lifecycle: shutdown
    # -----------------------------------------------------------------------

    async def shutdown_all(self) -> None:
        """
        Shut down every initialized plugin.

        Errors during shutdown are caught and logged. We give every plugin
        a chance to clean up — one plugin's misbehavior does not prevent
        others from running their teardown.
        """
        for name in list(self._initialized):
            plugin = self._plugins[name]
            try:
                await plugin.shutdown()
                self._logger.info("plugin_shutdown", plugin_name=name)
            except Exception as exc:
                self._logger.error(
                    "plugin_shutdown_failed",
                    plugin_name=name,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
            finally:
                self._initialized.discard(name)
