"""Pluggable planner backbones (PI R2: local Ollama default, hosted switch)."""

from .backbone import (  # noqa: F401
    Action,
    Backbone,
    PlanningContext,
    ScriptedBackbone,
    make_backbone,
)
