from torproxy.paths import user_directories


def test_linux_paths_follow_xdg_environment(tmp_path):
    paths = user_directories(
        environ={"XDG_CONFIG_HOME": str(tmp_path / "cfg"), "XDG_DATA_HOME": str(tmp_path / "data"),
                 "XDG_CACHE_HOME": str(tmp_path / "cache"), "XDG_STATE_HOME": str(tmp_path / "state")},
        home=tmp_path, system="Linux",
    )
    assert paths.config == tmp_path / "cfg" / "torproxy"
    assert paths.data == tmp_path / "data" / "torproxy"
    assert paths.logs == tmp_path / "state" / "torproxy" / "logs"


def test_windows_paths_use_appdata(tmp_path):
    paths = user_directories(environ={"APPDATA": str(tmp_path / "roam"),
                                      "LOCALAPPDATA": str(tmp_path / "local")}, home=tmp_path, system="Windows")
    assert paths.config == tmp_path / "roam" / "TorProxy"
    assert paths.data == tmp_path / "local" / "TorProxy"
