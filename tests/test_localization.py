from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_persian_translates_ui_labels_and_preserves_ltr_layout():
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QLabel

    from ui_.window.i18n import LanguageManager

    app = QApplication.instance() or QApplication([])
    previous_direction = app.layoutDirection()
    previous_font = app.font()
    manager = LanguageManager(app, "fa")
    label = QLabel("Disconnect")

    try:
        manager.translate_tree(label)

        assert label.text() == "قطع اتصال"
        assert app.layoutDirection() == Qt.LayoutDirection.LeftToRight

        manager.set_language("en")
        assert label.text() == "Disconnect"
        assert app.layoutDirection() == Qt.LayoutDirection.LeftToRight
    finally:
        app.removeEventFilter(manager)
        app.setFont(previous_font)
        app.setLayoutDirection(previous_direction)


def test_persian_translation_keeps_technical_values_and_translates_dynamic_counts():
    from ui_.window.i18n import translate_text

    assert translate_text("0 bridges", "fa") == "0 پل"
    assert translate_text("3 profiles", "fa") == "3 پروفایل"
    assert translate_text("2 / 5 rules", "fa") == "2 / 5 قاعده"
    assert translate_text("2 installed bundle(s)", "fa") == "2 بستهٔ نصب‌شده"

    assert translate_text("SOCKS5", "fa") == "SOCKS5"
    assert translate_text("127.0.0.1:9050", "fa") == "127.0.0.1:9050"
    assert translate_text("Disconnect", "en") == "Disconnect"
