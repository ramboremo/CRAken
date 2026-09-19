from pathlib import Path
import tempfile
import pytest
from crascanner.discovery import discover_files, classify_file_type


def test_classify_file_type():
    pe_cat, is_bin, is_exe = classify_file_type(Path("app.dll"))
    assert "PE Binary" in pe_cat
    assert is_bin is True
    assert is_exe is True

    manifest_cat, is_bin, is_exe = classify_file_type(Path("app.deps.json"))
    assert manifest_cat == "Dependency Manifest"
    assert is_bin is False


def test_discover_files_recursive():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        sub = root / "subdir"
        sub.mkdir()

        (root / "test1.exe").write_bytes(b"MZ\x00\x00test_binary")
        (sub / "test2.dll").write_bytes(b"MZ\x00\x00test_library")
        (root / "readme.txt").write_text("hello world")

        inventory = discover_files(root)
        assert len(inventory) == 3

        names = {f.path.name for f in inventory}
        assert names == {"test1.exe", "test2.dll", "readme.txt"}

        exe_item = next(f for f in inventory if f.path.name == "test1.exe")
        assert exe_item.is_executable is True
        assert exe_item.is_binary is True
