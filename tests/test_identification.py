from pathlib import Path
import tempfile
from crascanner.discovery import DiscoveredFile
from crascanner.fingerprint import FingerprintedFile
from crascanner.identification.nsrl import NSRLDatabase, CURATED_PLATFORM_HASHES
from crascanner.identification.catalog import HumanVerificationCatalog
from crascanner.identification.engine import ComponentIdentificationEngine


def test_nsrl_curated_lookup():
    nsrl = NSRLDatabase()
    # Check one of the curated platform hashes
    sample_hash = list(CURATED_PLATFORM_HASHES.keys())[0]
    is_match, details = nsrl.is_in_nsrl(sample_hash)
    assert is_match is True
    assert details is not None


def test_human_verification_catalog():
    with tempfile.TemporaryDirectory() as tmpdir:
        cat_file = Path(tmpdir) / "catalog.json"
        catalog = HumanVerificationCatalog(cat_file)

        catalog.add(
            sha256="abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            name="CustomInternalLib",
            version="2.1.0",
            purl="pkg:generic/CustomInternalLib@2.1.0",
            classification="Product Code",
            notes="Manually approved internal library",
        )

        # Reload
        catalog2 = HumanVerificationCatalog(cat_file)
        entry = catalog2.get("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
        assert entry is not None
        assert entry.name == "CustomInternalLib"
        assert entry.version == "2.1.0"


def test_component_identification_engine():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        p = root / "test_comp.dll"
        p.write_bytes(b"test")

        disc = DiscoveredFile(
            path=p,
            relative_path="test_comp.dll",
            size_bytes=4,
            extension=".dll",
            file_type="PE Binary (Windows)",
            is_binary=True,
            is_executable=True,
        )
        fp = FingerprintedFile(
            discovered=disc,
            sha256="1111222233334444555566667777888899990000111122223333444455556666",
            sha512="abcd" * 32,
        )

        engine = ComponentIdentificationEngine()
        results = engine.process_files([fp], root)
        assert len(results) == 1
        comp = results[0]
        assert comp.name is not None
        assert comp.confidence_level in (1, 2, 3, 4)
