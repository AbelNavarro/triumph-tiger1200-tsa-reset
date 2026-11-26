"""Offline: public CLI and guard exclude unrelated protected operations."""
import pathlib, sys, subprocess
root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
import tsa_adaption_reset as m
from tsa_analysis import demo_report, summary, parse_dtcs
assert hasattr(m.TxGuard, "assert_oneshot_allowed")
assert hasattr(m.Elm327, "exchange_once")
for frame in ("2701","27020000","1003","31017014","14FFFFFF","1101","3400","3600"):
    try:
        m.TxGuard(None).assert_tx_allowed(frame)
    except m.SafetyError:
        pass
    else:
        raise AssertionError(frame)
assert "Not adapted" in summary(demo_report())
assert parse_dtcs(bytes.fromhex("59020817020008"))["records"][0]["confirmed"]
for arg in ("--l3-reset", "--clear-dtcs", "--capture-session", "--seed-probe"):
    result = subprocess.run([sys.executable, str(root/"tsa_adaption_reset.py"), arg], capture_output=True)
    assert result.returncode == 2, arg
for f in ("2703","2704ABCD","2705","2706ABCD","2702AABBCCDD","81","20","1101","14FFFFFF","3400","3600","31017013"):
    try:
        m.TxGuard(None).assert_oneshot_allowed(f)
    except m.SafetyError:
        pass
    else:
        raise AssertionError(f)
result = subprocess.run([sys.executable, str(root/"tsa_adaption_reset.py"), "--demo"], capture_output=True)
assert result.returncode == 0, result.stderr
assert b"OFFLINE" in result.stdout
print("Public scope and synthetic demo passed")
