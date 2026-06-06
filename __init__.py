"""
Agent Scrutiny

Zero-trust security for AI agents. Every agent, under scrutiny.

Never trust. Always verify. Build secure AI.
"""

from agent_scrutiny.models import (
    AgentInteraction,
    Decision,
    EvaluationContext,
    InteractionType,
    PluginVerdict,
    SecurityVerdict,
    Severity,
)

__version__ = "0.1.0-dev"
__author__ = "Zero-Trust AI Contributors"
__license__ = "MIT"

# Stage 0: Foundation
# Stage 1: Core data models now available. Scrutinizer core, detectors, and
#          plugin system land next.

__all__ = [
    # Package metadata
    "__version__",
    "__author__",
    "__license__",
    # Core data models (Stage 1)
    "AgentInteraction",
    "Decision",
    "EvaluationContext",
    "InteractionType",
    "PluginVerdict",
    "SecurityVerdict",
    "Severity",
]
