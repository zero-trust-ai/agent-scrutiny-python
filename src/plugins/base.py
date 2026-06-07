"""
Agent Scrutiny — Plugin Base Class

This module defines the abstract Plugin class that every Agent Scrutiny plugin
implements. The contract mirrors the language-agnostic Plugin Specification
(docs/plugins/plugin-specification.md) — Python and Rust SDKs each provide
their own implementation of the same semantics.

Plugin authors subclass Plugin, declare name/version/description, and implement
the evaluate() coroutine. Helper methods (allow, warn, block) construct
PluginVerdicts with plugin metadata pre-filled — authors do not need to
restate name and version in every verdict.

Timing is measured by the PluginManager, not by the plugin itself. Plugins
return verdicts with evaluation_duration_ms=0.0; the manager overwrites it via
model_copy with the externally-measured elapsed time.

References:
    Plugin Spec      — docs/plugins/plugin-specification.md
    Plugin Ecosystem — docs/plugins/index.md
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    PluginVerdict,
)


class Plugin(ABC):
    """
    Abstract base class for Agent Scrutiny plugins.

    A conforming plugin implements:
        * Three abstract properties: name, version, description.
        * One abstract coroutine: evaluate(interaction, context) -> PluginVerdict.

    A plugin may optionally override:
        * required_context() — declare context keys this plugin needs.
        * initialize(config) — set up resources at load time.
        * shutdown() — release resources at unload time.

    Example:
        class GreetingDetector(Plugin):
            @property
            def name(self) -> str:
                return "greeting-detector"

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def description(self) -> str:
                return "Flags inputs that lack a greeting."

            async def evaluate(self, interaction, context):
                if "hello" not in interaction.agent_input.lower():
                    return self.warn(
                        explanation="No greeting found.",
                        threats=["no_greeting"],
                        confidence=0.3,
                    )
                return self.allow()
    """

    # -----------------------------------------------------------------------
    # Required contract — properties
    # -----------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """
        The plugin's unique identifier.

        Convention: kebab-case (lowercase letters, digits, hyphens only).
        Examples: "smart-contract-security", "financial-transfer-guard".

        Must be globally unique within any Scrutinizer instance.
        Max 64 characters.
        """
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """
        The plugin's version as a semantic version string.

        Examples: "1.2.3", "0.1.0-alpha.1". See https://semver.org.
        """
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """
        A one-sentence description of what the plugin does.

        Appears in the plugin registry and in Scrutinizer logs.
        Max 200 characters.
        """
        ...

    # -----------------------------------------------------------------------
    # Required contract — methods
    # -----------------------------------------------------------------------

    @abstractmethod
    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        """
        The core detection logic. Called once per agent interaction.

        This method is on the hot path. It is called for every interaction
        the Scrutinizer processes. Implementations must be fast — if the
        plugin needs to call an external service, consider whether that
        latency is acceptable, or whether to cache or batch.

        Args:
            interaction: The agent interaction to evaluate.
            context: Metadata accompanying the interaction.

        Returns:
            A PluginVerdict. Use the helper methods (self.allow, self.warn,
            self.block) to construct verdicts without restating plugin name
            and version.

        Implementations may raise. The PluginManager catches exceptions and
        converts them to a BLOCK verdict with the error preserved — but
        plugins should still aim to return verdicts for foreseeable errors
        rather than raising.
        """
        ...

    # -----------------------------------------------------------------------
    # Optional contract — overrideable methods with sensible defaults
    # -----------------------------------------------------------------------

    def required_context(self) -> list[str]:
        """
        Context keys this plugin needs in order to function.

        The Scrutinizer logs a warning (but does not fail) if an evaluation
        is called without these keys in the EvaluationContext metadata.
        Plugins that strictly require context should handle the missing-key
        case in evaluate() themselves.

        Returns an empty list by default — override if your plugin requires
        specific context keys.
        """
        return []

    async def initialize(self, config: dict[str, Any] | None = None) -> None:
        """
        Called once when the plugin is loaded by the PluginManager.

        Use this to set up resources: open database connections, load
        pattern files, parse configuration, warm caches.

        If initialization fails, raise an exception. The PluginManager will
        log the failure and exclude the plugin from future evaluations.

        Default implementation is a no-op. Override if your plugin needs
        setup.
        """
        pass

    async def shutdown(self) -> None:
        """
        Called when the plugin is being unloaded or the Scrutinizer is
        shutting down.

        Use this to release resources acquired in initialize(): close
        connections, flush logs, etc.

        Default implementation is a no-op. Override if your plugin holds
        resources.
        """
        pass

    # -----------------------------------------------------------------------
    # Verdict construction helpers
    # -----------------------------------------------------------------------

    def allow(
        self,
        *,
        explanation: str = "No threats detected.",
        confidence: float = 1.0,
        evidence: dict[str, Any] | None = None,
    ) -> PluginVerdict:
        """
        Construct an ALLOW PluginVerdict with this plugin's name and version
        pre-filled.

        evaluation_duration_ms is set to 0.0 in the returned verdict; the
        PluginManager replaces it with the externally-measured elapsed time
        before aggregation.
        """
        return self._verdict(
            decision=Decision.ALLOW,
            confidence=confidence,
            threats=[],
            explanation=explanation,
            evidence=evidence,
        )

    def warn(
        self,
        *,
        explanation: str,
        threats: list[str],
        confidence: float,
        evidence: dict[str, Any] | None = None,
    ) -> PluginVerdict:
        """
        Construct a WARN PluginVerdict with this plugin's name and version
        pre-filled.

        WARN means "allow but flag for monitoring" — use this for low- to
        medium-confidence detections that should not block traffic but should
        appear in audit logs.
        """
        return self._verdict(
            decision=Decision.WARN,
            confidence=confidence,
            threats=threats,
            explanation=explanation,
            evidence=evidence,
        )

    def block(
        self,
        *,
        explanation: str,
        threats: list[str],
        confidence: float,
        evidence: dict[str, Any] | None = None,
    ) -> PluginVerdict:
        """
        Construct a BLOCK PluginVerdict with this plugin's name and version
        pre-filled.

        Use this only when you are confident the interaction should be
        rejected. BLOCK verdicts cause the Scrutinizer to reject the request
        outright (in STRICT and PERMISSIVE modes).
        """
        return self._verdict(
            decision=Decision.BLOCK,
            confidence=confidence,
            threats=threats,
            explanation=explanation,
            evidence=evidence,
        )

    def _verdict(
        self,
        *,
        decision: Decision,
        confidence: float,
        threats: list[str],
        explanation: str,
        evidence: dict[str, Any] | None,
    ) -> PluginVerdict:
        """Internal verdict factory — keeps the public helpers DRY."""
        return PluginVerdict(
            plugin_name=self.name,
            plugin_version=self.version,
            decision=decision,
            confidence=confidence,
            threats=threats,
            explanation=explanation,
            evidence=evidence,
            evaluation_duration_ms=0.0,  # Overwritten by the PluginManager.
        )

    # -----------------------------------------------------------------------
    # Introspection
    # -----------------------------------------------------------------------

    def __repr__(self) -> str:
        # Subclasses get a sensible repr for free, drawing from the contract.
        try:
            return (
                f"{type(self).__name__}("
                f"name={self.name!r}, version={self.version!r})"
            )
        except NotImplementedError:
            return f"{type(self).__name__}(<uninstantiable>)"
