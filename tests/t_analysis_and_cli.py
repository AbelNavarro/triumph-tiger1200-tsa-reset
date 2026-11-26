"""Offline: tsa_analysis edge cases and CLI modes (--demo, --analyze, --analyze-bundle, --list-ports)."""
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import types
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import tsa_analysis as a
import tsa_session as ts

# 1. assess_firmware verdicts: matched, different, inconclusive
def _cal_hex(text):
    return (b"\x49\x04\x01" + text.encode("ascii").ljust(16, b"\x00")).hex()


matched = a.assess_firmware({
    "calibration_discovery": {"payload_hex": _cal_hex("0030174ECM")},
    "identification": {"F1A7": {"status": "ok", "hex": "201701"}},
})
assert matched["verdict"] == "matched", matched

diff_cal = a.assess_firmware({
    "calibration_discovery": {"payload_hex": _cal_hex("0030999ECM")},
    "identification": {"F1A7": {"status": "ok", "hex": "201701"}},
})
assert diff_cal["verdict"] == "different", diff_cal

diff_key = a.assess_firmware({
    "calibration_discovery": {"payload_hex": _cal_hex("0030174ECM")},
    "identification": {"F1A7": {"status": "ok", "hex": "201999"}},
})
assert diff_key["verdict"] == "different", diff_key

inc = a.assess_firmware({
    "calibration_discovery": {"payload_hex": None},
    "identification": {"F1A7": {"status": "ok", "hex": "201701"}},
})
assert inc["verdict"] == "inconclusive", inc

# 2. warning_indicator_lines: all three rules
rule1 = a.warning_indicator_lines({
    "status": "ok", "mask": "AF", "status_availability_mask": "AF",
    "records": [{"dtc_hex": "170200", "status_hex": "89", "warning_requested": True,
                 "confirmed": True, "test_failed": True, "pending": False}],
})
assert any("warningIndicatorRequested set on 170200" in ln for ln in rule1), rule1

rule2 = a.warning_indicator_lines({
    "status": "ok", "mask": "AF", "status_availability_mask": "AF", "records": [],
})
assert any("none from the engine ECU" in ln for ln in rule2), rule2

rule3_pending_only = a.warning_indicator_lines({
    "status": "ok", "mask": "04", "status_availability_mask": "FF", "records": [],
})
assert any("undetermined" in ln for ln in rule3_pending_only), rule3_pending_only

rule3_no_mask = a.warning_indicator_lines({"status": "no warning mask accepted", "attempts": []})
assert any("undetermined" in ln for ln in rule3_no_mask), rule3_no_mask

# 3. summarize_tsa_diagnostics: gear adaptation + 013C ADC thresholds + NRC resilience
diag_lines = a.summarize_tsa_diagnostics({
    "0300": {"status": "ok", "hex": "00ff"},
    "0301": {"status": "ok", "hex": "0000"},
    "0303": {"status": "nrc", "nrc": "0x31", "nrc_name": "requestOutOfRange"},
    "013C": {"status": "ok", "hex": "85"},
})
joined = "\n".join(diag_lines)
assert "0300" in joined and "Adapted" in joined, joined
assert "0301" in joined and "Not adapted" in joined, joined
assert "0303" in joined and "NRC 0x31" in joined, joined
assert "nominal rest window" in joined, joined

assert "low fault rail" in "\n".join(a.summarize_tsa_diagnostics({"013C": {"status": "ok", "hex": "18"}}))
assert "high fault rail" in "\n".join(a.summarize_tsa_diagnostics({"013C": {"status": "ok", "hex": "D9"}}))
assert "outside rest window" in "\n".join(a.summarize_tsa_diagnostics({"013C": {"status": "ok", "hex": "A0"}}))
assert a.summarize_tsa_diagnostics(None) == []
assert a.summarize_tsa_diagnostics({}) == []

# 4. read_report validation & CLI --analyze / --analyze-bundle
with tempfile.TemporaryDirectory() as td:
    tp = pathlib.Path(td)
    good = tp / "report.json"
    good.write_text(json.dumps({"report_version": 4, "report": a.demo_report()}), encoding="utf-8")
    loaded = a.read_report(good)
    assert loaded["shift_force_status_did"]["hex"] == "0000"

    bad = tp / "bad.json"
    bad.write_text(json.dumps({"report_version": 99, "report": {}}), encoding="utf-8")
    try:
        a.read_report(bad)
    except ValueError:
        pass
    else:
        raise AssertionError("read_report accepted unsupported version")

    res = subprocess.run([sys.executable, str(ROOT / "tsa_adaption_reset.py"), "--analyze", str(good)],
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert "OFFLINE" in res.stdout and "nominal rest window" in res.stdout, res.stdout

    # Reject --port on offline modes
    for args in (["--demo", "--port", "COM4"], ["--list-ports", "--port", "COM4"],
                 ["--analyze", str(good), "--port", "COM4"]):
        r = subprocess.run([sys.executable, str(ROOT / "tsa_adaption_reset.py")] + args,
                           capture_output=True, text=True)
        assert r.returncode == 2, (args, r.returncode)

    # Create a synthetic bundle and inspect it via --analyze-bundle
    broot = tp / "bundle"
    bundle = ts.CaptureBundle(broot, {"synthetic": True, "mode": "l1-reset-now"})
    bundle.snapshot("baseline", a.demo_report())
    bundle.finalize("completed", "summary line", [{"id": "q1", "question": "Q?", "answered": True, "answer": "yes"}],
                    {"persistence": "adapted after ignition cycle"})
    r = subprocess.run([sys.executable, str(ROOT / "tsa_adaption_reset.py"), "--analyze-bundle", str(broot)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "Bundle status: completed" in r.stdout and "adapted after ignition cycle" in r.stdout, r.stdout

# 5. --list-ports with stubbed serial ports (read-only, never opens a port)
fake = types.ModuleType("serial")
fake.SerialException = type("SerialException", (Exception,), {})
tools = types.ModuleType("serial.tools")
lp = types.ModuleType("serial.tools.list_ports")


class FakePortInfo:
    def __init__(self, device, description, hwid=""):
        self.device, self.description, self.name, self.hwid = device, description, device, hwid


lp.comports = lambda: [
    FakePortInfo("COM3", "Communications Port"),
    FakePortInfo("COM4", "Standard Serial over Bluetooth link (COM4)"),
]
tools.list_ports = lp
fake.tools = tools
sys.modules.update({"serial": fake, "serial.tools": tools, "serial.tools.list_ports": lp})

import tsa_adaption_reset as core
core.serial = fake
buf = io.StringIO()
with redirect_stdout(buf):
    rc = core.main(["--list-ports"])
assert rc == 0
out = buf.getvalue()
assert "COM3" in out and "COM4" in out and "[Bluetooth/ELM candidate]" in out, out

print("ANALYSIS_AND_CLI_OK")
