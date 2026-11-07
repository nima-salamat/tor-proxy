"""Browser descriptors shared by discovery, launch and UI."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Browser:
    id: str
    name: str
    family: str
    executable: str
    arguments: tuple[str, ...] = ()
    source: str = "detected"
    desktop_file: str | None = None

    def __post_init__(self) -> None:
        if self.family not in {"chromium", "firefox"}:
            raise ValueError("Browser family must be 'chromium' or 'firefox'.")
        if not self.id or not self.name or not self.executable:
            raise ValueError("Browser id, name and executable are required.")
