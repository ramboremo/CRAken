import hashlib
from pathlib import Path
import tempfile
from crascanner.discovery import DiscoveredFile
from crascanner.fingerprint import compute_hashes, fingerprint_files


def test_compute_hashes():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"BSI TR-03183-2 CRA Integrity Test")
        tf_path = Path(tf.name)

    try:
        sha256, sha512 = compute_hashes(tf_path)

        expected_256 = hashlib.sha256(b"BSI TR-03183-2 CRA Integrity Test").hexdigest()
        expected_512 = hashlib.sha512(b"BSI TR-03183-2 CRA Integrity Test").hexdigest()

        assert sha256 == expected_256
        assert sha512 == expected_512
        assert len(sha256) == 64
        assert len(sha512) == 128
    finally:
        tf_path.unlink(missing_ok=True)


def test_fingerprint_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / "sample.bin"
        p.write_bytes(b"sample data")

        disc = DiscoveredFile(
            path=p,
            relative_path="sample.bin",
            size_bytes=len(b"sample data"),
            extension=".bin",
            file_type="Binary Data",
            is_binary=True,
            is_executable=False,
        )

        results = fingerprint_files([disc])
        assert len(results) == 1
        assert results[0].sha256 == hashlib.sha256(b"sample data").hexdigest()
        assert results[0].sha512 == hashlib.sha512(b"sample data").hexdigest()
