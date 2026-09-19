from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple


@dataclass
class AIVerdict:
    """Structured AI Evaluation result."""
    is_false_positive: str  # "yes" or "no"
    justification: str


class AntigravityAIBridge:
    """
    Step 7: AI Internet Validation & Reasoning using Antigravity CLI (agy).
    Uses 'agy -p' to research CVEs with internet grounding and evaluate false-positives.
    """

    def __init__(self, agy_bin: Optional[str] = None, timeout_sec: int = 60):
        self.agy_bin = agy_bin or self._find_agy()
        self.timeout_sec = timeout_sec

    def _find_agy(self) -> Optional[str]:
        # Check standard Windows location
        local_agy = Path(os.environ.get("LOCALAPPDATA", "")) / "agy" / "bin" / "agy.exe"
        if local_agy.exists():
            return str(local_agy)
        return shutil.which("agy") or shutil.which("agy.exe")

    def is_available(self) -> bool:
        return bool(self.agy_bin and Path(self.agy_bin).exists())

    def evaluate_vulnerability(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        file_path: str,
        classification: str,
    ) -> AIVerdict:
        """
        Sends CVE and component context to Antigravity CLI to evaluate false positive status.
        Returns structured AIVerdict: is_false_positive ('yes' or 'no') and a 1-sentence justification.
        """
        if not self.is_available():
            return AIVerdict(
                is_false_positive="no",
                justification="AI evaluation skipped (Antigravity CLI not detected or disabled).",
            )

        prompt = (
            f"You are a Cyber Resilience Act (CRA) compliance auditor. Analyze this security vulnerability finding:\n"
            f"- CVE/Vulnerability ID: {cve_id}\n"
            f"- Component: {component_name} v{component_version}\n"
            f"- File: {file_path}\n"
            f"- Classification: {classification}\n\n"
            f"Research this CVE and evaluate whether this is a false positive for this component in this context.\n"
            f"Respond with JSON ONLY in this exact schema without any markdown wrapping or extra text:\n"
            f'{{"is_false_positive": "yes" or "no", "justification": "<concise 1-sentence explanation>"}}'
        )

        try:
            cmd = [self.agy_bin, "-p", prompt]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                check=False,
            )

            if proc.returncode == 0 and proc.stdout:
                output = proc.stdout.strip()
                # Clean up any potential markdown code blocks
                if output.startswith("```"):
                    lines = output.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    output = "\n".join(lines).strip()

                # Extract JSON substring if needed
                json_match = re.search(r"\{.*\}", output, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group(0))
                    is_fp = str(data.get("is_false_positive", "no")).strip().lower()
                    if is_fp not in ("yes", "no"):
                        is_fp = "yes" if "yes" in is_fp or "true" in is_fp else "no"
                    justification = str(data.get("justification", "Evaluated by AI.")).strip()
                    return AIVerdict(is_false_positive=is_fp, justification=justification)

            return AIVerdict(
                is_false_positive="no",
                justification="AI response inconclusive; retained as potential finding for review.",
            )
        except subprocess.TimeoutExpired:
            return AIVerdict(
                is_false_positive="no",
                justification="AI evaluation timed out; retained for review.",
            )
        except Exception as e:
            return AIVerdict(
                is_false_positive="no",
                justification=f"AI evaluation could not complete ({type(e).__name__}).",
            )

    def infer_root_package(
        self,
        vulnerable_component: str,
        vulnerable_version: str,
        top_level_components: List[str],
    ) -> str:
        """
        Fallback Method: Incurs AI reasoning to infer the most probable direct package responsible
        for pulling in a transitive vulnerable component.
        """
        if not self.is_available():
            return f"{vulnerable_component} (AI inference unavailable)"

        comps_str = ", ".join(top_level_components[:30])
        prompt = (
            f"You are a software dependency analyzer. A vulnerable transitive component was detected:\n"
            f"- Vulnerable Component: {vulnerable_component} v{vulnerable_version}\n"
            f"- Top-level components in this application: {comps_str}\n\n"
            f"Which directly-referenced root package is most likely responsible for bringing in this vulnerable dependency?\n"
            f"Respond with JSON ONLY in this format without markdown:\n"
            f'{{"likely_root_package": "<package name>"}}'
        )

        try:
            cmd = [self.agy_bin, "-p", prompt]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                output = proc.stdout.strip()
                json_match = re.search(r"\{.*\}", output, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group(0))
                    pkg = data.get("likely_root_package")
                    if pkg:
                        return f"{pkg} (AI-inferred, may be inaccurate)"

            return f"{vulnerable_component} (AI-inferred, may be inaccurate)"
        except Exception:
            return f"{vulnerable_component} (AI-inferred, may be inaccurate)"
