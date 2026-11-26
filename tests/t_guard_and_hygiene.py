"""Offline: exhaustive TxGuard, AT allowlist, keepalive lock isolation, and source hygiene."""
import pathlib
import re
import sys
import threading
import time
import types

fake = types.ModuleType("serial")
fake.SerialException = type("SerialException", (Exception,), {})
tools = types.ModuleType("serial.tools")
lp = types.ModuleType("serial.tools.list_ports")
lp.comports = lambda: []
tools.list_ports = lp
fake.tools = tools
sys.modules.update({"serial": fake, "serial.tools": tools, "serial.tools.list_ports": lp})

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import tsa_adaption_reset as m


class NullLog:
    def event(self, *a): pass
    def tx(self, *a): pass
    def rx(self, *a): pass


g = m.TxGuard(NullLog())

# 1. Read-only service frames (including new TSA diagnostic DIDs)
for ok in (
    "0100", "03", "07", "0902", "0904", "0906", "1001", "1081", "3E00",
    "1902FF", "190208", "1902AF", "19022F", "190204", "190A", "1901FF",
    "22F190", "22F18C", "22F1A7", "22F1A0",
    "220300", "220301", "220302", "220303", "220304", "220305", "220306",
    "220307", "220308", "22013C",
):
    assert g.assert_tx_allowed(ok) == ok.upper()

# 2. One-shot repair frames: strictly level-1 shift-force reset only
for ok in ("1003", "2701", "27020000", "2702ABCD", "27 02 ab cd", "31017014", "31037014"):
    g.assert_oneshot_allowed(ok)

for bad in (
    "1001", "1002", "1081", "2702", "270200", "2702000000", "2702AABBCCDD",
    "2703", "2704ABCD", "2705", "2706ABCD",
    "31017013", "31027014", "31017015", "31037013",
    "14FFFFFF", "1101", "81", "20", "3400", "3500", "3600", "37", "2E030200FF",
    "220302", "3E00", "", "2702ZZZZ", "270",
):
    try:
        g.assert_oneshot_allowed(bad)
    except m.SafetyError:
        pass
    else:
        raise AssertionError(f"one-shot guard accepted forbidden frame: {bad!r}")

# 3. Adapter AT command allowlist
for ok in (
    "ATZ", "ATI", "ATE0", "ATL0", "ATS1", "ATH1", "ATRV", "ATAR", "ATMA",
    "ATCAF1", "ATAT0", "ATAT1", "ATSP6", "ATSP7", "ATCP 18",
    "ATST 32", "ATST FF", "ATSH 7E0", "ATSH DAD5F1",
    "ATCRA 7E8", "ATCRA 18DAF1D5",
):
    g.assert_at_allowed(ok)

for bad in (
    "ATCAF0", "ATPP 01 SV 00", "ATWM 3E00", "ATSW 00", "ATBRD 0A",
    "STPO", "STPX h:DAD5F1", "ATSP0", "ATSP8", "ATSP9", "ATCSM1",
    "ATCF 600", "ATCM 600", "ATSH 1234", "ATCRA 1234", "AT", "", "2701",
):
    try:
        g.assert_at_allowed(bad)
    except m.SafetyError:
        pass
    else:
        raise AssertionError(f"AT guard accepted forbidden command: {bad!r}")

# 4. Keepalive isolation while Elm327.reset_sequence_lock() is held
class FakePort:
    def __init__(self):
        self.tx_log = []
        self._buf = bytearray()
        self._lock = threading.Lock()

    def reset_input_buffer(self):
        with self._lock:
            self._buf.clear()

    def write(self, data):
        cmd = data.decode("ascii").strip()
        with self._lock:
            self.tx_log.append(cmd)
            if cmd.startswith("AT"):
                reply = b"OK\r>"
            elif cmd == "3E00":
                reply = b"18 DA F1 D5 02 7E 00\r>"
            elif cmd == "2701":
                reply = b"18 DA F1 D5 04 67 01 12 34\r>"
            elif cmd.startswith("2702"):
                reply = b"18 DA F1 D5 02 67 02\r>"
            elif cmd == "31017014":
                reply = b"18 DA F1 D5 04 71 01 70 14\r>"
            else:
                reply = b"NO DATA\r>"
            self._buf.extend(reply)
        return len(data)

    def read(self, n):
        with self._lock:
            if not self._buf:
                return b""
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out

    def close(self):
        pass


elm = object.__new__(m.Elm327)
elm.log = NullLog()
elm.guard = g
elm.timeout = 2.0
elm.port = "SYNTH"
elm.baud = 115200
elm.ser = FakePort()
elm._lock = threading.RLock()
elm._sh = "DAD5F1"
elm._cra = "18DAF1D5"
elm._proto = "7"
elm._session_sub = None
elm.ka_enabled = True
elm._ka_interval = 0.01
elm._ka_thread = None
elm._ka_stop = threading.Event()
elm._hold_session = True
elm._session_activity = {"last": time.monotonic(), "longest": 0.0}
elm.changing_stage = True
elm.link_uncertain = False
elm.on_exchange = None

elm.start_keepalive(interval=0.01)
try:
    time.sleep(0.05)  # let keepalive tick before locking
    with elm.reset_sequence_lock():
        r1 = elm.exchange_once("2701", timeout=2.0)
        time.sleep(0.04)
        r2 = elm.exchange_once("27025E18", timeout=2.0)
        time.sleep(0.04)
        r3 = elm.exchange_once("31017014", timeout=2.0)
    assert r1["outcome"] == "positive"
    assert r2["outcome"] == "positive"
    assert r3["outcome"] == "positive"
    time.sleep(0.05)  # let keepalive resume after unlock
finally:
    elm.stop_keepalive()

service_tx = [c for c in elm.ser.tx_log if not c.startswith("AT")]
i_seed = service_tx.index("2701")
i_key = service_tx.index("27025E18")
i_reset = service_tx.index("31017014")
assert service_tx[i_seed:i_reset + 1] == ["2701", "27025E18", "31017014"], service_tx
assert "3E00" in service_tx[i_reset + 1:], f"keepalive did not resume after lock: {service_tx}"

# 5. Static source hygiene scan of production Python modules
prod_files = sorted(ROOT.glob("tsa_*.py"))
assert len(prod_files) == 5, prod_files
forbidden_patterns = (
    (r"\b[A-HJ-NPR-Z0-9]{17}\b", "VIN-shaped 17-character literal"),
    (r"\b[A-Z][0-9]{9}\b", "ECU-serial-shaped literal"),
    (r"TuneECU", "vendor name left in production code"),
    (r"APK analysis", "stale APK analysis wording"),
    (r"2702[0-9A-Fa-f]{4}", "hardcoded SecurityAccess key frame"),
)
serial_open_count = 0
for p in prod_files:
    text = p.read_text(encoding="utf-8")
    for pat, label in forbidden_patterns:
        assert not re.search(pat, text), f"{p.name} contains {label} ({pat})"
    serial_open_count += len(re.findall(r"\bserial\.Serial\s*\(", text))
assert serial_open_count == 1, f"expected Elm327._open to be sole serial.Serial opener, found {serial_open_count}"

print("GUARD_LOCK_AND_HYGIENE_OK")
