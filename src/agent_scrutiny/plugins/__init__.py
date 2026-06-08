"""
Agent Scrutiny — Plugin Subsystem

Stage 1 components:
    * Plugin        — abstract base class for all plugins (base.py)
    * PluginManager — lifecycle and dispatch coordinator (manager.py)

Stage 2 will add:
    * Plugin registry and discovery
    * plugin.yaml manifest spec
    * The first official plugin (smart-contract-security)
"""

from agent_scrutiny.plugins.base import Plugin
from agent_scrutiny.plugins.manager import PluginManager

__all__ = [
    "Plugin",
    "PluginManager",
]
