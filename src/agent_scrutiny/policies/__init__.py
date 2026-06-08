"""
Agent Scrutiny — Policy Subsystem

Stage 1 components:
    * Policy        — abstract base class for security policies (base.py)
    * PolicyEngine  — sequential policy evaluator with error containment (engine.py)
    * Built-in policies (builtin.py):
        - ThresholdPolicy
        - RequireMultipleThreatsPolicy
        - ThreatCategoryPolicy
        - AgentAllowlistPolicy

Policies transform SecurityVerdicts after plugin/detector aggregation. They
are the configuration-as-code half of the framework — detectors describe
what's in the data; policies describe what to do about it.
"""

from agent_scrutiny.policies.base import Policy
from agent_scrutiny.policies.builtin import (
    AgentAllowlistPolicy,
    RequireMultipleThreatsPolicy,
    ThreatCategoryPolicy,
    ThresholdPolicy,
)
from agent_scrutiny.policies.engine import PolicyEngine

__all__ = [
    # Core abstractions
    "Policy",
    "PolicyEngine",
    # Built-in policies
    "AgentAllowlistPolicy",
    "RequireMultipleThreatsPolicy",
    "ThreatCategoryPolicy",
    "ThresholdPolicy",
]