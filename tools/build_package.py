"""Build the public repair preview ZIP from an explicit file allowlist."""
from pathlib import Path
import hashlib
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dist"
NAME = "triumph-tiger1200-tsa-repair-preview"
FILES = (
    "README.md", "LICENSE", "QUICKSTART.md", "FINDINGS.md",
    "ECU-REFERENCE.md", "RESEARCH-HISTORY.md", "COMPATIBILITY.md", "SAFETY.md",
    "CONTRIBUTING.md", "SECURITY.md", "CITATION.cff", "requirements.txt",
    "tsa_adaption_reset.py", "tsa_analysis.py", "tsa_reset_evidence.py", "tsa_session.py",
    "tsa_security_access.py", "ACCESS-PROVENANCE.md",
    "tests/run_all.py",
    "tests/t_analysis_and_cli.py",
    "tests/t_guard2.py",
    "tests/t_guard_and_hygiene.py",
    "tests/t_l1_repair.py",
    "tests/t_package.py",
    "tests/t_public_scope.py",
    "tests/t_recovery_trace.py",
    "tests/t_reset_evidence.py",
    "tests/t_transport_integrity.py",
)


def _git_commit():
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(ROOT), stderr=subprocess.DEVNULL, text=True,
        ).strip()
        return out or "unknown"
    except Exception:
        return "unknown"


def main():
    OUT.mkdir(exist_ok=True)
    target = OUT / (NAME + ".zip")
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name in FILES:
            z.write(ROOT / name, NAME + "/" + name)
        z.writestr(NAME + "/BUILD_COMMIT", _git_commit() + "\n")
    checksum = hashlib.sha256(target.read_bytes()).hexdigest()
    (OUT / "SHA256SUMS.txt").write_text(checksum + "  " + target.name + "\n", encoding="ascii")
    print(target)

if __name__ == "__main__":
    main()
