from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from torproxy.bundle import BundleVerificationError


def test_expected_bundle_error_logs_without_traceback(caplog):
    pytest.importorskip("PySide6")
    from ui_.worker.worker import Worker

    class Signal:
        def __init__(self):
            self.value = None

        def emit(self, value=None):
            self.value = value

    signals = SimpleNamespace(started=Signal(), finished=Signal(), error=Signal())

    def fail():
        raise BundleVerificationError("Both official Tor distribution endpoints refused the connection.")

    worker = Worker(fail)
    worker.signals = signals
    with caplog.at_level(logging.WARNING, logger="ui_.worker.worker"):
        worker.run()

    records = [r for r in caplog.records if r.name == "ui_.worker.worker"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert records[0].exc_info is None
    assert "Both official Tor distribution endpoints" in records[0].message
    assert signals.error.value.startswith("BundleVerificationError:")
