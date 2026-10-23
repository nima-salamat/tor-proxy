from types import SimpleNamespace

import tor as tor_adapter
from torproxy.tor_manager import TorState


class _FakeData:
    def __init__(self):
        self.value = ""
        self.values = []

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value
        self.values.append(value)


def test_log_reported_100_percent_does_not_mark_tor_connected_before_ready(monkeypatch):
    monkeypatch.setattr(tor_adapter, "_find_executable", lambda _candidate: (None, None))
    runner = tor_adapter.TorRunner(19550, 19551, 19552)
    data = _FakeData()
    runner.app_window = SimpleNamespace(data=data)
    reports = []
    runner.log_message.connect(reports.append)

    runner._on_status(TorState.BOOTSTRAPPING, 100, "Done")
    assert data.value == "Verifying Tor listeners…"

    runner._on_status(TorState.READY, 100, "Tor bootstrap completed; SOCKS listener is accepting connections.")
    assert data.value == "100%"
    assert any("— Done" in report for report in reports)
