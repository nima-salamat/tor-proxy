"""Isolated browser launch support for TorProxy."""
from .detector import BrowserDetector
from .launchers import BrowserLaunchError, BrowserLauncher
from .models import Browser
from .profiles import BrowserProfileManager
from .registry import CustomBrowserStore

__all__ = [
    "Browser",
    "BrowserDetector",
    "BrowserLaunchError",
    "BrowserLauncher",
    "BrowserProfileManager",
    "CustomBrowserStore",
]
