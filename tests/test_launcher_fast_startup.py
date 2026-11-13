"""Guard startup-latency optimizations against regressions."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_linux_bootstrap_starts_python_before_loading_qt_runtime():
    source = (ROOT / "launcher" / "src" / "bootstrap.cpp").read_text(encoding="utf-8")
    linux = source[source.rfind("#else\n#include <cerrno>"):]
    assert "fork()" in linux
    assert "TORPROXY_LAUNCHER_STATUS_FILE" in linux
    assert "TORPROXY_LAUNCHER_PID" in linux
    assert linux.index("fork()") < linux.index("execv(gui.c_str()")


def test_linux_qt_launcher_attaches_to_child_without_artificial_delay():
    source = (ROOT / "launcher" / "src" / "main.cpp").read_text(encoding="utf-8")
    assert "pollPrestartedProcess()" in source
    assert "waitpid(child" in source
    assert "QTimer::singleShot(80" not in source
    assert "controller.start();" in source


def test_splash_caches_static_background_and_uses_lower_cpu_animation():
    header = (ROOT / "launcher" / "src" / "splash_window.h").read_text(encoding="utf-8")
    source = (ROOT / "launcher" / "src" / "splash_window.cpp").read_text(encoding="utf-8")
    assert "m_backgroundCache" in header
    assert "rebuildBackgroundCache()" in source
    assert "setInterval(50)" in source


def test_windows_launcher_starts_application_before_optional_logo_decode():
    source = (ROOT / "launcher" / "src" / "bootstrap.cpp").read_text(encoding="utf-8")
    win_main = source[source.index("int WINAPI wWinMain"):source.rfind("#else\n#include <cerrno>")]
    assert win_main.index("createWindow(state, instance)") < win_main.index("startApp(state)")
    assert win_main.index("startApp(state)") < win_main.rindex("loadSplashLogo(state)")
