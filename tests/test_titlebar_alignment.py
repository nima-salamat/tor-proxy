from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qt_app():
    pytest.importorskip("PySide6")
    try:
        from PySide6.QtWidgets import QApplication
    except (ImportError, OSError) as exc:
        pytest.skip(f"Qt native libraries are unavailable in this environment: {exc}")
    return QApplication.instance() or QApplication([])


def test_custom_titlebar_branding_is_left_aligned_and_controls_are_right_aligned(qt_app):
    from PySide6.QtWidgets import QMainWindow
    from ui_.window.custom_titlebar import CustomTitleBar

    class _TitleBarHost(QMainWindow):
        def hide_to_tray(self):
            self.hide()

    parent = _TitleBarHost()
    titlebar = CustomTitleBar(parent)
    layout = titlebar.layout()

    # Logo and title occupy the first two slots; the flexible spacer separates
    # them from the window controls on the right.
    assert layout.indexOf(titlebar.app_icon) == 0
    assert layout.indexOf(titlebar.title) == 1
    assert layout.itemAt(2).spacerItem() is not None
    assert layout.indexOf(titlebar.btn_min) == 3
    assert layout.indexOf(titlebar.btn_max) == 4
    assert layout.indexOf(titlebar.btn_close) == 5

    titlebar.deleteLater()
    parent.deleteLater()
    qt_app.processEvents()
