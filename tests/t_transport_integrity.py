"""Corrupted CAN replies must never look like successful ECU reads."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tsa_adaption_reset as m

class Log:
    def event(self, *args):
        pass

elm = object.__new__(m.Elm327)  # Never opens a port.
elm._proto = "7"
elm._cra = "18DAF1D5"
elm.log = Log()
h = "18 DA F1 D5 "
good = [h + "10 08 62 F1 8C 00 11 22", h + "21 33 44 AA AA AA AA AA"]
assert elm._reassemble(good) == bytes.fromhex("62f18c0011223344")
assert elm._reassemble(["18DAF1D5 05 62 03 02 00 FF"]) == bytes.fromhex("62030200ff")
assert elm._reassemble(["62 03 02 00 FF"]) == bytes.fromhex("62030200ff")
for broken in (
    good[:1], good[1:], good[::-1], good + good[1:],
    [good[0], good[1].replace("21 ", "22 ")],
    [good[0], good[1].replace("D5", "D6")],
    [good[0], h + "21 33"], [h + "05 62 03 02 00"],
    [h + "00"], [h + "10"], [h + "30 00 00"],
    [h + "05 62 03 02 00 FF", h + "05 62 03 02 00 00"],
    ["18DAF1D6 05 62 03 02 00 FF"],
    [good[0], "21 33 44"],
):
    assert elm._reassemble(broken) is None, broken
    assert not elm._interpret(broken)["ok"], broken

# Correct sequence-number wrap for a long response.
data = bytes(range(120))
frames = [h + "10 78 " + data[:6].hex(" ")]
for n, pos in enumerate(range(6, 120, 7), 1):
    frames.append(h + f"{0x20 | (n & 15):02X} " + data[pos:pos+7].hex(" "))
assert elm._reassemble(frames) == data
elm._proto, elm._cra = "6", "7E8"
assert elm._reassemble(["7E8 03 7F 22 31"]) == bytes.fromhex("7f2231")
assert elm._reassemble(["7E9 03 7F 22 31"]) is None

elm._proto, elm._cra, elm._sh = "7", None, "DAD5F1"
assert elm._reassemble(["18DAF1D6 05 62 03 02 00 FF"]) is None
assert elm._reassemble(["18DAF1D5 05 62 03 02 00 FF"]) == bytes.fromhex("62030200ff")
for payload in ("7f22", "7f223100", "7f1931"):
    result = m.parse_rdbi("0302", {"negative": True, "bytes": bytes.fromhex(payload)})
    assert result["status"] == "unexpected"
assert m.parse_rdbi("0302", {"ok": True, "bytes": bytes.fromhex("6203010000")})["status"] == "unexpected"

class UnrelatedReply:
    def at(self, *args, **kwargs):
        return ["OK"]
    def set_addressing(self, *args):
        pass
    def obd(self, *args, **kwargs):
        return {"ok": True, "bytes": b"\x62" * 20}

m.time.sleep = lambda _: None
assert not m.phase0(UnrelatedReply(), Log()), "an arbitrary long payload is not a VIN trust test"
print("TRANSPORT_INTEGRITY_OK")

# Pending replies preceding the final response, within one ELM transaction.
elm._proto, elm._cra, elm._sh = "7", "18DAF1D5", "DAD5F1"
pending = h + "03 7F 19 78"
final = h + "07 59 02 FF 17 02 00 09"
for prefix in ([pending], [pending + " AA AA AA AA", pending]):
    result = elm._interpret(prefix + [final], request_service=0x19)
    assert result["ok"] and result["bytes"].hex() == "5902ff17020009"
multi = [h + "10 0B 59 02 FF 17 02 00", h + "21 09 17 03 00 08 AA AA"]
assert elm._interpret([pending] + multi, request_service=0x19)["bytes"].hex() == "5902ff1702000917030008"
for bad in (
    [pending] + multi[:1],
    [pending, final.replace("D5", "D6")],
    [pending.replace("D5", "D6"), final],
    [pending.replace("19", "22"), final],
    [pending, pending.replace("19", "22"), final],
    [pending, h + "05 62 03 02 00 00"],
    [pending, h + "03 7F 22 31"],
    [final, pending],
    [pending] + [multi[0], multi[1].replace("21 ", "22 ")],
):
    assert not elm._interpret(bad, request_service=0x19)["ok"], bad
for prefix in ([pending], [pending, pending]):
    result = elm._interpret(prefix, request_service=0x19)
    assert result["negative"] and result["nrc"] == 0x78 and not result["ok"]
result = elm._interpret([pending, h + "03 7F 19 31"], request_service=0x19)
assert result["negative"] and result["nrc"] == 0x31
assert elm._interpret(["7F 19 78", "59 02 FF"], request_service=0x19)["ok"]
elm._proto, elm._cra, elm._sh = "6", "7E8", "7E0"
assert elm._interpret(["7E8 03 7F 19 78", "7E8 03 59 02 FF"], request_service=0x19)["ok"]
print("PENDING_RESPONSE_TESTS_OK")
