"""Offline: verify allowlisted ZIP build, SHA-256 checksum, BUILD_COMMIT, and clean extraction."""
import hashlib
import pathlib
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILDER = ROOT / "tools" / "build_package.py"

if not BUILDER.exists():
    # Running inside an already-extracted preview ZIP: verify BUILD_COMMIT exists.
    commit = (ROOT / "BUILD_COMMIT").read_text(encoding="ascii").strip()
    assert commit, "BUILD_COMMIT is empty in extracted package"
    print("EXTRACTED_PACKAGE_OK")
    sys.exit(0)

res = subprocess.run([sys.executable, str(BUILDER)], cwd=str(ROOT), capture_output=True, text=True)
assert res.returncode == 0, res.stderr

dist = ROOT / "dist"
zpath = dist / "triumph-tiger1200-tsa-repair-preview.zip"
sums = (dist / "SHA256SUMS.txt").read_text(encoding="ascii").strip()
digest = hashlib.sha256(zpath.read_bytes()).hexdigest()
assert sums == f"{digest}  {zpath.name}", (sums, digest)

with zipfile.ZipFile(zpath) as zf:
    names = set(zf.namelist())
    prefix = "triumph-tiger1200-tsa-repair-preview/"
    assert prefix + "BUILD_COMMIT" in names, "BUILD_COMMIT missing from ZIP"
    commit = zf.read(prefix + "BUILD_COMMIT").decode("ascii").strip()
    assert commit, "BUILD_COMMIT is empty"
    # Every test file in tests/t_*.py must be packaged
    for t in sorted((ROOT / "tests").glob("t_*.py")):
        assert f"{prefix}tests/{t.name}" in names, f"missing from build_package allowlist: {t.name}"
    # No private / forbidden artifacts may ever enter the ZIP
    for name in names:
        low = name.lower()
        assert not any(low.endswith(ext) for ext in (".hex", ".apk", ".btsnoop", ".pcap", ".log", ".bin")), name

    with tempfile.TemporaryDirectory() as td:
        zf.extractall(td)
        extracted = pathlib.Path(td) / "triumph-tiger1200-tsa-repair-preview"
        # -S skips site-packages, proving --demo runs without pyserial installed.
        demo = subprocess.run([sys.executable, "-S", str(extracted / "tsa_adaption_reset.py"), "--demo"],
                              cwd=str(extracted), capture_output=True, text=True)
        assert demo.returncode == 0 and "OFFLINE" in demo.stdout, demo.stderr + demo.stdout
        suite = subprocess.run([sys.executable, str(extracted / "tests" / "run_all.py")],
                               cwd=str(extracted), capture_output=True, text=True)
        assert suite.returncode == 0, suite.stdout + suite.stderr

print("PACKAGE_BUILD_AND_CLEAN_EXTRACT_OK")
