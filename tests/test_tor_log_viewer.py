from __future__ import annotations

from pathlib import Path

from torproxy.tor_manager import TorManager, TorSettings
from ui_.window.tor_log_dialog import read_log_page_before, read_log_tail


def test_bootstrap_log_parser_understands_control_port_and_notice_formats():
    assert TorManager._parse_bootstrap_log_line(
        '[notice] Bootstrapped 0% (starting): Starting'
    ) == (0, "Starting")
    assert TorManager._parse_bootstrap_log_line(
        'NOTICE BOOTSTRAP PROGRESS=12 TAG=conn_done SUMMARY="Connected to a relay"'
    ) == (12, "Connected to a relay")
    assert TorManager._parse_bootstrap_log_line(
        '[notice] Bootstrapped 100% (done): Done'
    ) == (100, "Done")
    assert TorManager._parse_bootstrap_log_line("[warn] Bridge connection failed") is None


def test_bootstrap_log_updates_read_only_new_appended_lines(tmp_path):
    manager = TorManager(TorSettings(executable=tmp_path / "tor", data_directory=tmp_path / "data"))
    manager.log_path = tmp_path / "logs" / "tor.log"
    manager.log_path.parent.mkdir()
    manager.log_path.write_text(
        '[notice] Bootstrapped 0% (starting): Starting\n',
        encoding="utf-8",
    )
    manager._bootstrap_log_offset = 0

    assert manager._read_bootstrap_log_updates() == [(0, "Starting")]
    assert manager._read_bootstrap_log_updates() == []

    with manager.log_path.open("a", encoding="utf-8") as handle:
        handle.write('[notice] Bootstrapped 10% (conn_done): Connected to a relay\n')
    assert manager._read_bootstrap_log_updates() == [(10, "Connected to a relay")]


def test_live_log_clear_truncates_file_and_keeps_active_handle_writable(tmp_path):
    manager = TorManager(TorSettings(executable=tmp_path / "tor", data_directory=tmp_path / "data"))
    manager.log_path = tmp_path / "logs" / "tor.log"
    manager.log_path.parent.mkdir()
    handle = manager.log_path.open("ab", buffering=0)
    manager._log_handle = handle
    handle.write(b"old notice line\n")
    try:
        manager.clear_log_file()
        assert manager.log_path.read_bytes() == b""
        handle.write(b"new notice line\n")
        assert manager.log_path.read_bytes() == b"new notice line\n"
    finally:
        handle.close()
        manager._log_handle = None


def test_tail_and_older_pages_have_no_gaps_or_duplicates(tmp_path):
    path = tmp_path / "tor.log"
    rows = [f"line-{index:03d}" for index in range(20)]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    tail, cursor, size = read_log_tail(path, 5)
    assert [text for _offset, text in tail] == rows[-5:]
    assert size == path.stat().st_size

    older, older_cursor = read_log_page_before(path, cursor, 5)
    assert [text for _offset, text in older] == rows[-10:-5]
    assert older_cursor == older[0][0]

    oldest, oldest_cursor = read_log_page_before(path, older_cursor, 5)
    assert [text for _offset, text in oldest] == rows[-15:-10]
    assert oldest_cursor == oldest[0][0]


def test_log_tail_and_pagination_are_bounded(tmp_path):
    path = tmp_path / "tor.log"
    path.write_text("".join(f"entry-{index}\n" for index in range(5000)), encoding="utf-8")
    tail, cursor, _size = read_log_tail(path, 100)
    assert len(tail) == 100
    assert tail[0][1] == "entry-4900"
    older, _offset = read_log_page_before(path, cursor, 50)
    assert len(older) == 50
    assert older[0][1] == "entry-4850"


def test_live_log_viewer_has_a_clear_confirmation_and_bounded_buffer():
    from pathlib import Path
    import ast

    source = (Path(__file__).resolve().parents[1] / "ui_/window/tor_log_dialog.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert "clear_log_history" in names
    assert "_line_limit_changed" in names
    assert "load_older" in names
    assert "_poll_file" in names
    assert "QMessageBox.question" in source
    assert "AVAILABLE_LINE_LIMITS = (500, 1000, 2000, 5000)" in source
