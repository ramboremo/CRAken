import json
from pathlib import Path
import tempfile
from crascanner.discovery import DiscoveredFile
from crascanner.fingerprint import FingerprintedFile
from crascanner.identification.engine import IdentifiedComponent
from crascanner.attribution import RootPackageAttributor


def test_deps_json_deterministic_attribution():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        deps_path = root / "app.deps.json"

        # Mock .deps.json content
        deps_data = {
            "targets": {
                ".NETCoreApp,Version=v6.0": {
                    "MyDirectPackage/2.0.0": {
                        "dependencies": {
                            "VulnerableTransitive": "1.0.0"
                        },
                        "runtime": {
                            "lib/net6.0/MyDirectPackage.dll": {}
                        }
                    },
                    "VulnerableTransitive/1.0.0": {
                        "runtime": {
                            "lib/net6.0/VulnerableTransitive.dll": {}
                        }
                    }
                }
            }
        }
        with open(deps_path, "w", encoding="utf-8") as f:
            json.dump(deps_data, f)

        attributor = RootPackageAttributor(root)

        disc = DiscoveredFile(root / "VulnerableTransitive.dll", "VulnerableTransitive.dll", 100, ".dll", "PE Binary", True, True)
        fp = FingerprintedFile(disc, "1" * 64, "2" * 128)
        comp = IdentifiedComponent(
            fingerprint=fp,
            name="VulnerableTransitive",
            version="1.0.0",
            purl="pkg:nuget/VulnerableTransitive@1.0.0",
            confidence_level=3,
            confidence_description="Level 3",
            classification="Product Code",
            is_platform=False,
        )

        responsible_pkg = attributor.attribute_root_package(comp, [comp])
        assert responsible_pkg == "MyDirectPackage"
