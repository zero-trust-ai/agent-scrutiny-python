"""
Agent Scrutiny

Zero-trust security for AI agents. Every agent, under scrutiny.

Never trust. Always verify. Build secure AI.
"""

from agent_scrutiny.core import Mode, Scrutinizer
from agent_scrutiny.detectors import (
    DataExfiltrationDetector,
    InputValidator,
    PromptInjectionDetector,
)
from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    InteractionType,
    PluginVerdict,
    SecurityVerdict,
    Severity,
)
from agent_scrutiny.plugins import Plugin, PluginManager
from agent_scrutiny.policies import (
    AgentAllowlistPolicy,
    Policy,
    PolicyEngine,
    RequireMultipleThreatsPolicy,
    ThreatCategoryPolicy,
    ThresholdPolicy,
)

__version__ = "0.1.0-dev"
__author__ = "Zero-Trust AI Contributors"
__license__ = "MIT"

# Stage 0: Foundation
# Stage 1: All components landed —
#          data models, Scrutinizer, plugin system, prompt-injection detector,
#          input validator, data-exfiltration detector, policy engine + builtins.

__all__ = [
    # Package metadata
    "__version__",
    "__author__",
    "__license__",
    # Scrutinizer (Stage 1)
    "Scrutinizer",
    "Mode",
    # Plugin system (Stage 1)
    "Plugin",
    "PluginManager",
    # Built-in detectors (Stage 1)
    "DataExfiltrationDetector",
    "InputValidator",
    "PromptInjectionDetector",
    # Policy system (Stage 1)
    "Policy",
    "PolicyEngine",
    "AgentAllowlistPolicy",
    "RequireMultipleThreatsPolicy",
    "ThreatCategoryPolicy",
    "ThresholdPolicy",
    # Core data models (Stage 1)
    "AgentInteraction",
    "Decision",
    "EvaluationContext",
    "InteractionType",
    "PluginVerdict",
    "SecurityVerdict",
    "Severity",
]