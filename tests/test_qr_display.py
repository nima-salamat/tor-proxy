from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QApplication, QWidget


def test_qr_dot_widget_builds_a_matrix_with_a_four_module_quiet_zone(qt_app):
    from ui_.window.qr_display import QrCodeDotWidget

    widget = QrCodeDotWidget(
        "http://abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz.onion"
    )
    matrix = widget._matrix

    assert len(matrix) > 21
    assert all(len(row) == len(matrix) for row in matrix)
    assert all(not cell for row in matrix[:4] for cell in row)
    assert all(not cell for row in matrix[-4:] for cell in row)
    assert all(not row[column] for row in matrix for column in range(4))
    assert all(not row[column] for row in matrix for column in range(len(matrix) - 4, len(matrix)))
    assert widget._center_icon == "fa6s.shield-halved"
    widget.deleteLater()
    qt_app.processEvents()


def test_qr_button_accepts_a_payload_provider_and_uses_the_shared_window(qt_app, monkeypatch):
    import ui_.window.qr_display as qr_display

    owner = QWidget()
    payloads = []
    shown = []

    def payload_provider():
        payloads.append("called")
        return "http://exampleabcdefghijklmnopqrstuvwxyz.onion"

    def show(parent, payload, **kwargs):
        shown.append((parent, payload, kwargs))
        return 7

    monkeypatch.setattr(qr_display, "show_qr_code", show)
    button = qr_display.QrCodeButton(
        payload_provider,
        parent=owner,
        button_text="",
        title="Share service",
        description="Scan with Tor Browser.",
        display_value="example.onion",
        center_icon="fa6s.globe",
    )

    assert button.open_qr_code() == 7
    assert payloads == ["called"]
    assert shown == [(
        owner,
        "http://exampleabcdefghijklmnopqrstuvwxyz.onion",
        {
            "title": "Share service",
            "description": "Scan with Tor Browser.",
            "display_value": "example.onion",
            "center_icon": "fa6s.globe",
        },
    )]
    owner.close()
    owner.deleteLater()
    qt_app.processEvents()


def test_qr_dialog_uses_shared_custom_shell_and_copies_the_payload(qt_app):
    from ui_.window.dialogs import _FramelessDialog
    from ui_.window.qr_display import QrCodeDisplayDialog

    payload = "http://exampleabcdefghijklmnopqrstuvwxyz.onion"
    dialog = QrCodeDisplayDialog(
        None,
        payload,
        title="Share Onion address",
        description="Scan with Tor Browser.",
        display_value="exampleabcdefghijklmnopqrstuvwxyz.onion",
    )

    assert isinstance(dialog, _FramelessDialog)
    assert dialog.objectName() == "qrCodeDisplayDialog"
    assert dialog.qr_widget._center_icon == "fa6s.shield-halved"
    assert dialog.value_label.text() == "exampleabcdefghijklmnopqrstuvwxyz.onion"

    dialog.copy_payload()
    assert QApplication.clipboard().text() == payload
    assert dialog.copy_button.text() == "Copied"
    dialog._copy_timer.stop()
    dialog.close()
    dialog.deleteLater()
    qt_app.processEvents()


def test_developer_tor_service_address_has_a_reusable_qr_action():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "ui_/window/onion_hosting_page.py").read_text(encoding="utf-8")

    assert "from ui_.window.qr_display import QrCodeButton" in source
    assert 'qr_button = QrCodeButton(' in source
    assert 'f"http://{address}" if service.get("address") else ""' in source
    assert 'qr_button.setObjectName("onionQrButton")' in source
    assert 'qr_button.setEnabled(bool(service.get("address")))' in source
    assert 'This is a private service, so visitors also need its client authorization key.' in source
