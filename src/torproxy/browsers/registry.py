"""Persistent storage for user-added browser executables."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from torproxy.paths import user_directories

from .models import Browser


class CustomBrowserStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else user_directories().config / "custom_browsers.json"

    def list(self) -> list[Browser]:
        if not self.path.is_file():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(raw, list):
            return []
        browsers: list[Browser] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                browser = Browser(
                    id=str(item["id"]),
                    name=str(item["name"]),
                    family=str(item["family"]),
                    executable=str(item["executable"]),
                    arguments=tuple(str(arg) for arg in item.get("arguments", [])),
                    source="custom",
                )
            except (KeyError, TypeError, ValueError):
                continue
            executable_path = Path(browser.executable)
            if not executable_path.is_file():
                continue
            if os.name != "nt" and not os.access(executable_path, os.X_OK):
                continue
            browsers.append(browser)
        return browsers

    def add(self, browser: Browser) -> None:
        if browser.source != "custom":
            raise ValueError("Only custom browser entries can be stored here.")
        executable = Path(browser.executable)
        if not executable.is_file():
            raise ValueError("The selected browser executable does not exist.")
        if os.name != "nt" and not os.access(executable, os.X_OK):
            raise ValueError("The selected browser file is not executable.")
        entries = {item.id: item for item in self.list()}
        entries[browser.id] = browser
        payload = [
            {
                "id": item.id,
                "name": item.name,
                "family": item.family,
                "executable": item.executable,
                "arguments": list(item.arguments),
            }
            for item in sorted(entries.values(), key=lambda value: value.name.casefold())
        ]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=".custom-browsers-", suffix=".tmp", dir=self.path.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            if os.name != "nt":
                os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, self.path)
        except OSError:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise
