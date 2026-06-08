"""
Agent Scrutiny — Data Exfiltration Detector

A Plugin that detects common sensitive-data patterns in agent OUTPUTS,
catching information leakage before responses leave the system.

This is the symmetric counterpart to PromptInjectionDetector. Where the
injection detector scans agent_input for attack patterns trying to GET in,
this detector scans agent_output for sensitive data trying to GET out.

Default pattern library covers:

    * US Social Security Numbers (formatted)
    * Credit card numbers (Luhn-validated for precision)
    * AWS access key IDs
    * Cryptographic private key headers
    * GitHub personal access tokens
    * Email addresses (WARN level — many legitimate uses)

Stage 1 limitations:
    * English / US-formatted defaults. International formats (UK SSN-equivalent,
      EU IBAN, etc.) are not in the default library — add via custom_patterns.
    * No generic "API key" / high-entropy string detection. That requires
      entropy analysis, which is more involved and noisier than regex.
    * No PHI / medical data detection. That's plugin territory because
      legitimate-use patterns are domain-specific.
    * Detection only — no automatic redaction. The verdict reports what
      was found; the calling application decides whether to redact, block,
      or escalate.

References:
    Threat Model      — docs/threat-model.md (T2.1)
    Architecture      — docs/architecture.md (Detection Layer)
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    PluginVerdict,
)
from agent_scrutiny.plugins.base import Plugin


# ---------------------------------------------------------------------------
# Luhn algorithm — credit card number validation
# ---------------------------------------------------------------------------


def _luhn_check(card_number: str) -> bool:
    """
    Validate a string of digits using the Luhn algorithm.

    The Luhn algorithm is a checksum used by most major credit card networks:

        1. Starting from the rightmost digit and moving left, double every
           second digit.
        2. If doubling yields a two-digit number, subtract 9 (equivalent to
           summing the digits).
        3. Sum all the resulting digits.
        4. The number is valid if and only if the sum is divisible by 10.

    Args:
        card_number: A string that may contain digits along with spaces,
                     dashes, or other separators. Only the digits are used.

    Returns:
        True if the extracted digit sequence is a valid Luhn number with
        between 13 and 19 digits (the standard credit card range).
    """
    digits = "".join(c for c in card_number if c.isdigit())
    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    for i, digit_char in enumerate(reversed(digits)):
        digit = int(digit_char)
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


# ---------------------------------------------------------------------------
# Pattern model
# ---------------------------------------------------------------------------


class ExfiltrationPattern(BaseModel):
    """
    A single data-exfiltration detection pattern.

    Each pattern is a regex matched case-insensitively against the agent's
    output. Optional post-match validation (currently: Luhn check) further
    filters matches to reduce false positives.

    Example:
        ExfiltrationPattern(
            name="us_ssn",
            pattern=r"\\b\\d{3}-\\d{2}-\\d{4}\\b",
            threat_id="data_exfiltration.us_ssn",
            decision=Decision.BLOCK,
            confidence=0.95,
            description="US SSN in standard format.",
        )
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(
        description="Short identifier for this pattern (snake_case)."
    )
    pattern: str = Field(
        description="Regular expression matched case-insensitively against output."
    )
    threat_id: str = Field(
        description=(
            "Threat identifier surfaced in PluginVerdict.threats. "
            "Convention: 'data_exfiltration.<category>'."
        )
    )
    decision: Decision = Field(
        description=(
            "What this pattern's match implies. BLOCK for high-confidence "
            "exfiltration, WARN for context-dependent matches."
        )
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in the decision when this pattern matches.",
    )
    description: str = Field(
        description="Human-readable explanation of what this pattern catches."
    )
    requires_luhn: bool = Field(
        default=False,
        description=(
            "If True, the matched substring must also pass the Luhn checksum. "
            "Used to reduce false positives on credit-card patterns."
        ),
    )


# ---------------------------------------------------------------------------
# Default pattern library
# ---------------------------------------------------------------------------

DEFAULT_PATTERN_LIBRARY_VERSION = "0.1.0"

DEFAULT_PATTERNS: tuple[ExfiltrationPattern, ...] = (
    ExfiltrationPattern(
        name="us_ssn",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        threat_id="data_exfiltration.us_ssn",
        decision=Decision.BLOCK,
        confidence=0.95,
        description=(
            "US Social Security Number in standard XXX-XX-XXXX format. "
            "Unformatted 9-digit sequences are not matched — too ambiguous."
        ),
    ),
    ExfiltrationPattern(
        name="credit_card",
        pattern=r"\b(?:\d{4}[\s-]?){3}\d{1,7}\b",
        threat_id="data_exfiltration.credit_card",
        decision=Decision.BLOCK,
        confidence=0.95,
        description=(
            "Credit card number (13-19 digits, formatted in 4-digit groups). "
            "Validated with the Luhn algorithm to reject random digit strings."
        ),
        requires_luhn=True,
    ),
    ExfiltrationPattern(
        name="aws_access_key",
        pattern=r"\bAKIA[0-9A-Z]{16}\b",
        threat_id="data_exfiltration.aws_access_key",
        decision=Decision.BLOCK,
        confidence=0.99,
        description=(
            "AWS access key ID. Format is unmistakable and almost never "
            "appears legitimately in agent output."
        ),
    ),
    ExfiltrationPattern(
        name="private_key",
        pattern=(
            r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----"
        ),
        threat_id="data_exfiltration.private_key",
        decision=Decision.BLOCK,
        confidence=1.0,
        description=(
            "Cryptographic private key header. There is no legitimate reason "
            "for this to appear in agent output, ever."
        ),
    ),
    ExfiltrationPattern(
        name="github_token",
        pattern=r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b",
        threat_id="data_exfiltration.github_token",
        decision=Decision.BLOCK,
        confidence=0.99,
        description=(
            "GitHub personal access token (classic ghp_, fine-grained "
            "github_pat_ prefixes covered separately if needed)."
        ),
    ),
    ExfiltrationPattern(
        name="email_address",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        threat_id="data_exfiltration.email_address",
        decision=Decision.WARN,
        confidence=0.5,
        description=(
            "Email address. Many legitimate uses (customer service, "
            "notifications); flagged at WARN level so ops can decide based "
            "on context."
        ),
    ),
)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class DataExfiltrationDetector(Plugin):
    """
    Pattern-based detector for sensitive data in agent outputs.

    Scans the ``agent_output`` field of each interaction against a
    configurable library of regex patterns. Patterns with ``requires_luhn``
    set additionally pass the Luhn checksum filter. Matched patterns
    contribute their threat IDs and decisions to the resulting verdict,
    aggregated using "most severe wins."

    When ``agent_output`` is None (pre-output evaluation), the detector
    returns ALLOW immediately — there's nothing to check.

    Example:
        from agent_scrutiny import Scrutinizer, DataExfiltrationDetector

        scrutinizer = Scrutinizer(plugins=[DataExfiltrationDetector()])
        await scrutinizer.initialize()

        verdict = await scrutinizer.evaluate_interaction(
            agent_input="What's the test user's SSN?",
            agent_output="The test user's SSN is 123-45-6789.",
            agent_id="support-01",
        )
        assert verdict.is_blocked

    Custom pattern example:
        custom = ExfiltrationPattern(
            name="company_employee_id",
            pattern=r"\\bEMP-\\d{8}\\b",
            threat_id="data_exfiltration.company_employee_id",
            decision=Decision.BLOCK,
            confidence=0.95,
            description="Internal employee ID format.",
        )
        detector = DataExfiltrationDetector(custom_patterns=[custom])
    """

    @property
    def name(self) -> str:
        return "data-exfiltration-detector"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def description(self) -> str:
        return (
            "Pattern-based detection of sensitive data in agent outputs "
            f"(library v{DEFAULT_PATTERN_LIBRARY_VERSION})."
        )

    def __init__(
        self,
        custom_patterns: list[ExfiltrationPattern] | None = None,
        *,
        include_defaults: bool = True,
    ) -> None:
        """
        Args:
            custom_patterns: Additional patterns to check beyond the defaults.
                             Useful for domain-specific data formats
                             (internal IDs, regional formats, etc.).
            include_defaults: If False, only ``custom_patterns`` are used and
                              the default library is skipped. Useful when the
                              defaults conflict with legitimate output in a
                              specific application.
        """
        super().__init__()

        patterns: list[ExfiltrationPattern] = []
        if include_defaults:
            patterns.extend(DEFAULT_PATTERNS)
        if custom_patterns:
            patterns.extend(custom_patterns)
        self._patterns: tuple[ExfiltrationPattern, ...] = tuple(patterns)

        # Pre-compile every regex once at construction time.
        self._compiled: tuple[
            tuple[ExfiltrationPattern, re.Pattern[str]], ...
        ] = tuple(
            (p, re.compile(p.pattern, re.IGNORECASE | re.UNICODE))
            for p in self._patterns
        )

    @property
    def patterns(self) -> tuple[ExfiltrationPattern, ...]:
        """Read-only view of the active pattern library."""
        return self._patterns

    async def evaluate(
        self,
        interaction: AgentInteraction,
        context: EvaluationContext,
    ) -> PluginVerdict:
        """
        Scan ``interaction.agent_output`` for sensitive data patterns.

        Returns ALLOW immediately if there's no output to scan (pre-output
        evaluation). Otherwise, every pattern is checked, Luhn-validated
        where applicable, and verdicts are aggregated.
        """
        if interaction.agent_output is None:
            return self.allow(
                explanation="No output to scan (pre-output evaluation).",
            )

        text = interaction.agent_output

        matches: list[tuple[ExfiltrationPattern, str]] = []
        for pattern, compiled in self._compiled:
            for match in compiled.finditer(text):
                matched_text = match.group(0)
                if pattern.requires_luhn and not _luhn_check(matched_text):
                    # Pattern matched syntactically but the checksum doesn't
                    # validate — it's not a real card number, skip.
                    continue
                matches.append((pattern, matched_text))

        if not matches:
            return self.allow(explanation="No exfiltration patterns matched.")

        # Aggregate matches: most severe decision wins.
        block_matches = [m for m in matches if m[0].decision == Decision.BLOCK]
        warn_matches = [m for m in matches if m[0].decision == Decision.WARN]

        # Build evidence and deterministic threats list.
        evidence: dict[str, Any] = {
            "matched_patterns": _evidence_for_matches(matches),
            "pattern_library_version": DEFAULT_PATTERN_LIBRARY_VERSION,
        }

        # Preserve first-match order while deduplicating threats.
        threats: list[str] = []
        seen: set[str] = set()
        for pattern, _ in matches:
            if pattern.threat_id not in seen:
                seen.add(pattern.threat_id)
                threats.append(pattern.threat_id)

        pattern_names = sorted({p.name for p, _ in matches})
        explanation = (
            f"Matched {len(matches)} exfiltration pattern(s) in output: "
            f"{', '.join(pattern_names)}."
        )

        if block_matches:
            confidence = max(p.confidence for p, _ in block_matches)
            return self.block(
                explanation=explanation,
                threats=threats,
                confidence=confidence,
                evidence=evidence,
            )

        # warn_matches must be non-empty (we already returned on no matches).
        confidence = max(p.confidence for p, _ in warn_matches)
        return self.warn(
            explanation=explanation,
            threats=threats,
            confidence=confidence,
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _redact(matched_text: str) -> str:
    """
    Render a redacted form of a matched secret for safe inclusion in evidence.

    Reveals the first 4 and last 4 characters when the match is long enough;
    masks everything for short matches. Audit logs need enough information to
    correlate without re-leaking the secret.
    """
    if len(matched_text) <= 8:
        return "*" * len(matched_text)
    return f"{matched_text[:4]}{'*' * (len(matched_text) - 8)}{matched_text[-4:]}"


def _evidence_for_matches(
    matches: list[tuple[ExfiltrationPattern, str]],
) -> list[dict[str, Any]]:
    """
    Build the structured evidence list for matched patterns.

    Unlike PromptInjectionDetector, which can safely echo the attack phrase
    in evidence (it's not sensitive data), this detector REDACTS the matched
    text. The whole point is that the matched text IS the sensitive data —
    putting it verbatim in audit logs would re-leak what we just caught.
    """
    return [
        {
            "pattern_name": pattern.name,
            "matched_text_redacted": _redact(matched_text),
            "matched_length": len(matched_text),
            "threat_id": pattern.threat_id,
            "decision": pattern.decision.value,
            "confidence": pattern.confidence,
        }
        for pattern, matched_text in matches
    ]
