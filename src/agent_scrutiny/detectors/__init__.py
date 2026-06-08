"""
Agent Scrutiny — Built-in Detectors

Detectors that ship with the SDK. Each detector is implemented as a
Plugin subclass so it composes through the same evaluation pipeline as
third-party plugins; the distinction between "detector" and "plugin" is
purely about packaging — built-in versus third-party — not about code
path.

Stage 1 detectors:
    * PromptInjectionDetector    — input-side: catches injection attacks
    * InputValidator             — input-side: structural validation
    * DataExfiltrationDetector   — output-side: catches sensitive data leaks
"""

from agent_scrutiny.detectors.data_exfiltration import (
    DataExfiltrationDetector,
    ExfiltrationPattern,
)
from agent_scrutiny.detectors.data_exfiltration import (
    DEFAULT_PATTERN_LIBRARY_VERSION as DATA_EXFILTRATION_LIBRARY_VERSION,
)
from agent_scrutiny.detectors.data_exfiltration import (
    DEFAULT_PATTERNS as DATA_EXFILTRATION_DEFAULT_PATTERNS,
)
from agent_scrutiny.detectors.input_validator import InputValidator
from agent_scrutiny.detectors.prompt_injection import (
    DEFAULT_PATTERN_LIBRARY_VERSION as PROMPT_INJECTION_LIBRARY_VERSION,
)
from agent_scrutiny.detectors.prompt_injection import (
    DEFAULT_PATTERNS as PROMPT_INJECTION_DEFAULT_PATTERNS,
)
from agent_scrutiny.detectors.prompt_injection import (
    InjectionPattern,
    PromptInjectionDetector,
)

__all__ = [
    # Prompt injection
    "InjectionPattern",
    "PromptInjectionDetector",
    "PROMPT_INJECTION_DEFAULT_PATTERNS",
    "PROMPT_INJECTION_LIBRARY_VERSION",
    # Input validation
    "InputValidator",
    # Data exfiltration
    "DataExfiltrationDetector",
    "ExfiltrationPattern",
    "DATA_EXFILTRATION_DEFAULT_PATTERNS",
    "DATA_EXFILTRATION_LIBRARY_VERSION",
]
