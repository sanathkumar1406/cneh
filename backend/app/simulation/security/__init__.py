"""Security simulation, event detection, and educational scenarios."""

from .engine import SecurityEventEngine
from .events import AlertCategory, AlertSeverity, SecurityAlert

__all__ = [
    "AlertCategory",
    "AlertSeverity",
    "SecurityAlert",
    "SecurityEventEngine",
]
