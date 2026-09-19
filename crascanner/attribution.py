import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from crascanner.ai import AntigravityAIBridge
from crascanner.identification.engine import IdentifiedComponent


class RootPackageAttributor:
    """
    Step 7: Root Package Attribution (Level 1 findings only).
    Resolves which directly-referenced package is responsible for pulling in the vulnerable component,
    allowing developers to 'update package X' rather than manually modifying transient binaries.
    """

    def __init__(self, target_dir: Path, ai_bridge: Optional[AntigravityAIBridge] = None):
        self.target_dir = Path(target_dir).resolve()
        self.ai = ai_bridge or AntigravityAIBridge()
        self._deps_graphs: List[Dict] = []
        self._lock_graphs: List[Dict] = []
        self._load_manifests()

    def _load_manifests(self):
        """Scans for .deps.json or packages.lock.json in the target directory."""
        if not self.target_dir.exists():
            return

        for root, _, files in os.walk(self.target_dir):
            for f in files:
                f_path = Path(root) / f
                if f.endswith(".deps.json"):
                    try:
                        with open(f_path, "r", encoding="utf-8") as fp:
                            self._deps_graphs.append(json.load(fp))
                    except Exception:
                        pass
                elif f == "packages.lock.json" or f.endswith(".lock.json"):
                    try:
                        with open(f_path, "r", encoding="utf-8") as fp:
                            self._lock_graphs.append(json.load(fp))
                    except Exception:
                        pass

    def _resolve_from_deps_json(self, component_name: str) -> Optional[str]:
        """
        Deterministic resolution: parses .deps.json dependency trees.
        """
        comp_lower = component_name.lower()
        for graph in self._deps_graphs:
            targets = graph.get("targets", {})
            for target_name, packages in targets.items():
                # Step A: Find which packages list this component as a runtime/compile asset or dependency
                pullers = []
                for pkg_key, pkg_info in packages.items():
                    pkg_name = pkg_key.split("/")[0]
                    # Check runtime assets
                    runtime = pkg_info.get("runtime", {})
                    for r_path in runtime.keys():
                        if comp_lower in r_path.lower():
                            pullers.append(pkg_name)
                    # Check dependencies
                    deps = pkg_info.get("dependencies", {})
                    for dep_name in deps.keys():
                        dep_lower = dep_name.lower()
                        if comp_lower == dep_lower or comp_lower in dep_lower or dep_lower in comp_lower:
                            pullers.append(pkg_name)

                # Step B: Identify the highest-level direct package
                # A direct package is usually referenced in 'libraries' with type 'project' or top-level target
                if pullers:
                    # Return the shortest / most direct package name
                    return sorted(pullers, key=len)[0]

        return None

    def _resolve_from_lock_json(self, component_name: str) -> Optional[str]:
        """
        Deterministic resolution: parses packages.lock.json.
        """
        comp_lower = component_name.lower()
        for graph in self._lock_graphs:
            dependencies = graph.get("dependencies", {})
            for framework, pkgs in dependencies.items():
                if isinstance(pkgs, dict):
                    for pkg_name, pkg_data in pkgs.items():
                        if pkg_name.lower() == comp_lower:
                            # If direct dependency
                            if pkg_data.get("type", "").lower() == "direct":
                                return pkg_name
                        # Check transitive dependencies
                        transitive = pkg_data.get("dependencies", {})
                        for t_name in transitive.keys():
                            if t_name.lower() == comp_lower:
                                return pkg_name
        return None

    def attribute_root_package(
        self,
        component: IdentifiedComponent,
        all_components: List[IdentifiedComponent],
    ) -> str:
        """
        Attributes the responsible root package for a Level 1 finding:
        1. Primary method: Deterministic parse of .deps.json or packages.lock.json.
        2. Fallback method: AI inference via Antigravity CLI (agy).
        """
        # 1. Deterministic Method
        direct_pkg = self._resolve_from_deps_json(component.name)
        if direct_pkg:
            return direct_pkg

        direct_pkg = self._resolve_from_lock_json(component.name)
        if direct_pkg:
            return direct_pkg

        # If component is its own direct executable/top-level item
        if component.fingerprint.is_executable and component.relative_path.endswith(".exe"):
            return component.name

        # 2. Fallback Method: AI Inference
        top_level_names = [
            c.name for c in all_components
            if c.is_identified and c.name != component.name
        ]
        return self.ai.infer_root_package(
            vulnerable_component=component.name,
            vulnerable_version=component.version,
            top_level_components=top_level_names,
        )
