import io
import tarfile

import pytest

from torproxy.bundle import BundleVerificationError, safe_extract_tar_gz, sha256_file


def _write_tar(path, name, content=b"ok", kind=tarfile.REGTYPE):
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo(name)
        info.type = kind
        info.size = len(content) if kind == tarfile.REGTYPE else 0
        archive.addfile(info, io.BytesIO(content) if kind == tarfile.REGTYPE else None)


def test_sha256_is_computed(tmp_path):
    source = tmp_path / "sample"
    source.write_bytes(b"abc")
    assert sha256_file(source) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_safe_extraction_accepts_regular_files(tmp_path):
    archive = tmp_path / "bundle.tar.gz"
    destination = tmp_path / "extracted"
    _write_tar(archive, "tor/tor", b"payload")
    safe_extract_tar_gz(archive, destination)
    assert (destination / "tor" / "tor").read_bytes() == b"payload"


@pytest.mark.parametrize("name", ["../escape", "/absolute/escape", "dir/../../escape"])
def test_safe_extraction_rejects_path_traversal(tmp_path, name):
    archive = tmp_path / "bundle.tar.gz"
    _write_tar(archive, name, b"payload")
    with pytest.raises(BundleVerificationError, match="Unsafe path"):
        safe_extract_tar_gz(archive, tmp_path / "out")
    assert not (tmp_path / "escape").exists()


def test_safe_extraction_rejects_symlinks(tmp_path):
    archive = tmp_path / "bundle.tar.gz"
    _write_tar(archive, "linked", kind=tarfile.SYMTYPE)
    with pytest.raises(BundleVerificationError, match="Unsupported link"):
        safe_extract_tar_gz(archive, tmp_path / "out")


def test_extraction_refuses_to_overwrite_existing_destination(tmp_path):
    archive = tmp_path / "bundle.tar.gz"
    _write_tar(archive, "file", b"safe")
    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(BundleVerificationError, match="already exists"):
        safe_extract_tar_gz(archive, destination)
