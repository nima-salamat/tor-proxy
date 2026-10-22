from __future__ import annotations

import ast
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qt_app():
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _message_handler_capture():
    from PySide6.QtCore import qInstallMessageHandler

    warnings: list[str] = []
    previous = qInstallMessageHandler(
        lambda _mode, _context, message: warnings.append(message)
        if "QLayout: Attempting to add QLayout" in message
        else None
    )
    return warnings, previous, qInstallMessageHandler


def test_settings_and_main_window_construct_without_duplicate_layout_warning(qt_app, monkeypatch):
    try:
        import ui
        from PySide6.QtWidgets import QWidget
    except (ImportError, OSError) as exc:
        pytest.skip(f"Desktop UI native dependencies are unavailable in this environment: {exc}")

    class _FakeProxyWidget(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.tor = SimpleNamespace(path_set=False, MaxCircuitDirtiness=600)
            self.connected = False
            self.running = False

        def _stop_services(self):
            return None

    monkeypatch.setattr(ui, "ProxyWindow", _FakeProxyWidget)
    monkeypatch.setattr(ui, "IS_WINDOWS", False)
    warnings, previous, install_handler = _message_handler_capture()
    window = None
    try:
        window = ui.Window()
        qt_app.processEvents()
    finally:
        install_handler(previous)
        if window is not None:
            window.close()
            window.deleteLater()
            qt_app.processEvents()
    assert warnings == []


def test_layout_source_has_one_owner_per_root_and_no_widget_parented_nested_layout():
    repository = Path(__file__).resolve().parents[1]
    paths = [
        repository / "ui.py",
        repository / "ui_/window/setting_window.py",
        repository / "ui_/window/proxy_window.py",
        repository / "ui_/window/block_host_window.py",
        repository / "ui_/window/exclude_host_window.py",
    ]
    for path in paths:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        # Root layouts created with QWidget as parent already install themselves.
        # The previously problematic duplicate setLayout calls are therefore forbidden
        # for a variable initialized by Q*Layout(self).
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            parented_layouts = set()
            for child in ast.walk(node):
                if not isinstance(child, ast.Assign) or len(child.targets) != 1:
                    continue
                target = child.targets[0]
                value = child.value
                if (
                    isinstance(target, ast.Name)
                    and isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id in {"QVBoxLayout", "QHBoxLayout", "QGridLayout", "QFormLayout"}
                    and value.args
                    and isinstance(value.args[0], ast.Name)
                    and value.args[0].id == "self"
                ):
                    parented_layouts.add(target.id)
            for child in ast.walk(node):
                if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
                    continue
                if child.func.attr != "setLayout" or not child.args:
                    continue
                if isinstance(child.args[0], ast.Name) and child.args[0].id in parented_layouts:
                    pytest.fail(f"{path.name} redundantly attaches parent-owned layout '{child.args[0].id}'")
