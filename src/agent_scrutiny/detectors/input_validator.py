"""
Agent Scrutiny — Input Validator

Stage 1 lean implementation of structural input validation. Performs three
checks against the agent_input and agent_output fields:

    1. Size limit enforcement (Gate 1 in docs/input-validation.md terms).
    2. Null byte detection (a specific Gate 6 sub-case).
    3. Control-character density (another Gate 6 sub-case).

This is intentionally a smaller scope than the full Eight Validation Gates
specified in docs/input-validation.md. The Stage 1 SDK handles text-only
A2A/MCP payloads, so the file-handling gates (extension, content-type,
magic-byte, filename) are not applicable yet. When file payloads arrive in
Stage 2, those gates can be added without disrupting these checks.

Gate 6's primary payload — prompt-injection patterns — is implemented in
agent_scrutiny.detectors.prompt_injection. This validator handles the more
mundane structural checks (null bytes, control-character density) that
aren't really "patterns" but still belong in the same conceptual category.

Forward-looking note: every confidence weight is a constructor parameter,
so empirically-calibrated values can be supplied at deployment time without
patching the validator. This is the hook for the statistical-calibration
work that will matter as production data accumulates.

References:
    Input Validation Spec — docs/input-validation.md
    Threat Model          — docs/threat-model.md (T1.2 + DoS variants)
"""

from __future__ import annotations

from typing import Any

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    PluginVerdict,
)
from agent_scrutiny.plugins.base import Plugin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Legitimate whitespace controls. Everything else in the C0/C1 control ranges
# (plus DEL) counts as suspicious.
_LEGITIMATE_WHITESPACE = frozenset({"\t", "\n", "\r"})


def _is_suspicious_control_char(c: str) -> bool:
    """
    True iff c is a control character that has no legitimate use in agent
    input. Tabs, newlines, and carriage returns are explicitly excluded.
    """
    if c in _LEGITIMATE_WHITESPACE:
        return False
    cp = ord(c)
    # C0 controls (U+0000 to U+001F), DEL (U+007F), C1 controls (U+0080–U+009F).
    return cp < 0x20 or cp == 0x7F or (0x80 <= cp <= 0x9F)


def _control_char_ratio(text: str) -> float:
    """Fraction of the text that consists of suspicious control characters."""
    if not text:
        return 0.0
    suspicious = sum(1 for c in text if _is_suspicious_control_char(c))
    return suspicious / len(text)


# ---------------------------------------------------------------------------
# InputValidator
# ---------------------------------------------------------------------------


class InputValidator(Plugin):
    """
    Structural validator for agent inputs (and outputs, when present).

    Three independent checks, each with configurable thresholds and
    confidence weights:

        * Size: rejects payloads above ``max_input_length`` /
          ``max_output_length``. Decision: BLOCK.
        * Null bytes: rejects payloads containing the NUL character
          (U+0000). Decision: BLOCK. Can be disabled via
          ``block_null_bytes=False`` for the rare case where binary data
          legitimately appears in inputs.
        * Control-character density: WARN if the ratio of suspicious
          control characters exceeds ``max_control_char_ratio``. Tabs,
          newlines, and carriage returns are NOT counted as suspicious.

    Example:
        from agent_scrutiny import Scrutinizer, InputValidator

        scrutinizer = Scrutinizer(plugins=[
            InputValidator(max_input_length=50_000),
            # ... other plugins
        ])

    Statistical-calibration hook:
        Each violation type has its own confidence parameter. As production
        data accumulates, you can override defaults with empirically-tuned
        values — without changing this code.

            InputValidator(
                size_violation_confidence=0.95,
                null_byte_confidence=0.92,
                control_char_confidence=0.55,
            )
    """

    @property
    def name(self) -> str:
        return "input-validator"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def description(self) -> str:
        return (
            "Structural validation of agent inputs: size limits, null bytes, "
            "and control-character density."
        )

    def __init__(
        self,
        *,
        max_input_length: int = 100_000,
        max_output_length: int = 100_000,
        block_null_bytes: bool = True,
        max_control_char_ratio: float = 0.10,
        # Confidence weights — exposed as constructor params to support future
        # statistical calibration. Defaults reflect the determinism of each check.
        size_violation_confidence: float = 1.0,
        null_byte_confidence: float = 0.99,
        control_char_confidence: float = 0.7,
    ) -> None:
        """
        Args:
            max_input_length: Maximum allowed length of agent_input, in
                              characters. Default is 100 KB.
            max_output_length: Maximum allowed length of agent_output, in
                               characters. Default is 100 KB.
            block_null_bytes: If True, presence of any NUL character in the
                              payload causes a BLOCK verdict.
            max_control_char_ratio: Maximum fraction of suspicious control
                                    characters allowed before a WARN fires.
                                    Default is 10%.
            size_violation_confidence: Confidence value attached to verdicts
                                       resulting from size-limit violations.
            null_byte_confidence: Confidence value attached to verdicts
                                  resulting from null-byte detection.
            control_char_confidence: Confidence value attached to verdicts
                                     resulting from control-character density
                                     violations.

        Raises:
            ValueError: If any numeric parameter is out of range.
        """
        super().__init__()

        if max_input_length <= 0:
            raise ValueError("max_input_length must be positive")
        if max_output_length <= 0:
            raise ValueError("max_output_length must be positive")
        if not 0.0 <= max_control_char_ratio <= 1.0:
            raise ValueError(
                "max_control_char_ratio must be in [0.0, 1.0]"
            )
        for label, value in (
            ("size_violation_confidence", size_violation_confidence),
            ("null_byte_confidence", null_byte_confidence),
            ("control_char_confidence", control_char_confidence),
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{label} must be in [0.0, 1.0]")

        self.max_input_length = max_input_length
        self.max_output_length = max_output_length
        self.block_null_bytes = block_null_bytes
        self.max_control_char_ratio = max_control_char_ratio
        self.size_violation_confidence = size_violation_confidence
        self.null_byte_confidence = null_byte_confidence
        self.control_char_confidence = control_char_confidence

    # -----------------------------------------------------------------------
    # Main evaluation
    # -----------------------------------------------------------------------

    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        """
        Run all enabled checks against the input (and output, if present).

        Each check that fires produces a "violation" dict; the detector
        aggregates them using the same "most severe wins" rule the
        Scrutinizer applies to plugin verdicts.
        """
        violations: list[dict[str, Any]] = []

        # ---- Size checks --------------------------------------------------
        if len(interaction.agent_input) > self.max_input_length:
            violations.append(
                {
                    "check": "size",
                    "field": "agent_input",
                    "actual_length": len(interaction.agent_input),
                    "max_length": self.max_input_length,
                    "decision": Decision.BLOCK,
                    "confidence": self.size_violation_confidence,
                    "threat_id": "input_validation.oversized_input",
                }
            )

        if interaction.agent_output is not None:
            if len(interaction.agent_output) > self.max_output_length:
                violations.append(
                    {
                        "check": "size",
                        "field": "agent_output",
                        "actual_length": len(interaction.agent_output),
                        "max_length": self.max_output_length,
                        "decision": Decision.BLOCK,
                        "confidence": self.size_violation_confidence,
                        "threat_id": "input_validation.oversized_output",
                    }
                )

        # ---- Null byte checks ---------------------------------------------
        if self.block_null_bytes:
            if "\x00" in interaction.agent_input:
                violations.append(
                    {
                        "check": "null_byte",
                        "field": "agent_input",
                        "decision": Decision.BLOCK,
                        "confidence": self.null_byte_confidence,
                        "threat_id": "input_validation.null_byte",
                    }
                )
            if interaction.agent_output and "\x00" in interaction.agent_output:
                violations.append(
                    {
                        "check": "null_byte",
                        "field": "agent_output",
                        "decision": Decision.BLOCK,
                        "confidence": self.null_byte_confidence,
                        "threat_id": "input_validation.null_byte",
                    }
                )

        # ---- Control-character density ------------------------------------
        input_ratio = _control_char_ratio(interaction.agent_input)
        if input_ratio > self.max_control_char_ratio:
            violations.append(
                {
                    "check": "control_char_density",
                    "field": "agent_input",
                    "ratio": round(input_ratio, 4),
                    "threshold": self.max_control_char_ratio,
                    "decision": Decision.WARN,
                    "confidence": self.control_char_confidence,
                    "threat_id": "input_validation.excessive_control_chars",
                }
            )

        if interaction.agent_output is not None:
            output_ratio = _control_char_ratio(interaction.agent_output)
            if output_ratio > self.max_control_char_ratio:
                violations.append(
                    {
                        "check": "control_char_density",
                        "field": "agent_output",
                        "ratio": round(output_ratio, 4),
                        "threshold": self.max_control_char_ratio,
                        "decision": Decision.WARN,
                        "confidence": self.control_char_confidence,
                        "threat_id": "input_validation.excessive_control_chars",
                    }
                )

        # ---- Aggregate ----------------------------------------------------
        if not violations:
            return self.allow(explanation="Input passed all structural checks.")

        return self._aggregate_violations(violations)

    # -----------------------------------------------------------------------
    # Aggregation
    # -----------------------------------------------------------------------

    def _aggregate_violations(
        self,
        violations: list[dict[str, Any]],
    ) -> PluginVerdict:
        """Combine violations into a single verdict using 'most severe wins'."""
        block_violations = [
            v for v in violations if v["decision"] == Decision.BLOCK
        ]
        warn_violations = [v for v in violations if v["decision"] == Decision.WARN]

        # Preserve first-seen order while deduplicating threat IDs.
        threats: list[str] = []
        seen: set[str] = set()
        for v in violations:
            if v["threat_id"] not in seen:
                seen.add(v["threat_id"])
                threats.append(v["threat_id"])

        evidence: dict[str, Any] = {"violations": violations}

        check_names = sorted({v["check"] for v in violations})
        explanation_summary = (
            f"Found {len(violations)} input-validation violation(s): "
            f"{', '.join(check_names)}."
        )

        if block_violations:
            confidence = max(v["confidence"] for v in block_violations)
            return self.block(
                explanation=explanation_summary,
                threats=threats,
                confidence=confidence,
                evidence=evidence,
            )

        # warn_violations must be non-empty (we returned early on no violations).
        confidence = max(v["confidence"] for v in warn_violations)
        return self.warn(
            explanation=explanation_summary,
            threats=threats,
            confidence=confidence,
            evidence=evidence,
        )
