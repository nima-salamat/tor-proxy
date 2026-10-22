"""Operating-system-specific, per-user writable application paths."""
from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AppDirectories:
    config: Path
    data: Path
    cache: Path
    state: Path
    logs: Path

    def ensure(self) -> AppDirectories:
        for path in (self.config, self.data, self.cache, self.state, self.logs):
            path.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                try:
                    path.chmod(0o700)
                except OSError:
                    pass
        return self


def user_directories(app_name: str = "TorProxy", environ: dict[str, str] | None = None,
                     home: Path | None = None, system: str | None = None) -> AppDirectories:
    """Return standard per-user locations without touching the filesystem."""
    env = os.environ if environ is None else environ
    home = Path.home() if home is None else Path(home)
    system = platform.system() if system is None else system

    if system == "Windows":
        base = Path(env.get("LOCALAPPDATA", home / "AppData" / "Local")) / app_name
        config = Path(env.get("APPDATA", home / "AppData" / "Roaming")) / app_name
        data = base
        cache = base / "Cache"
        state = base / "State"
    elif system == "Darwin":
        base = home / "Library" / "Application Support" / app_name
        config = base / "Config"
        data = base
        cache = home / "Library" / "Caches" / app_name
        state = base / "State"
    else:
        config = Path(env.get("XDG_CONFIG_HOME", home / ".config")) / app_name.lower()
        data = Path(env.get("XDG_DATA_HOME", home / ".local" / "share")) / app_name.lower()
        cache = Path(env.get("XDG_CACHE_HOME", home / ".cache")) / app_name.lower()
        state = Path(env.get("XDG_STATE_HOME", home / ".local" / "state")) / app_name.lower()

    return AppDirectories(config=config, data=data, cache=cache, state=state, logs=state / "logs")
