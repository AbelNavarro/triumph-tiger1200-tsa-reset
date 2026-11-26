"""Offline regression of the public repair flow; no physical adapter is used."""
import tempfile, pathlib, sys, types
fake = types.ModuleType("serial")
fake.SerialException = type("SerialException", (Exception,), {})
sys.modules["serial"] = fake
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import tsa_adaption_reset as core
import tsa_session as ts
import tsa_security_access as sa
assert sa.d5_security_access_key(bytes.fromhex("0001")).hex() == "4b48"
assert sa.d5_security_access_key(bytes.fromhex("0000")).hex() == "0000"
for bad in (b"", b"1", b"123"):
    try: sa.d5_security_access_key(bad)
    except ValueError: pass
    else: raise AssertionError("bad seed length")
class Clock:
    def __init__(self): self.t = 0
    def __call__(self):
        self.t += 100
        return self.t
def run(path, refusal=None, decline=False):
    bundle = ts.CaptureBundle(path / "capture", {"synthetic": True})
    log = core.SessionLog(path / "log", quiet=True)
    elm = ts.DemoElm()
    elm.seed_l1 = bytes.fromhex("1234")
    elm.reset_nrc = refusal
    timeline = []
    chg, rd = elm.exchange_once, elm.obd
    def write(f, **kw):
        core.TxGuard(log).assert_oneshot_allowed(f)
        timeline.append(("write", f))
        return chg(f, **kw)
    def read(f, **kw):
        timeline.append(("read", f))
        return rd(f, **kw)
    elm.exchange_once, elm.obd = write, read
    def ask(prompt):
        if "Type UNVERIFIED" in prompt: return "UNVERIFIED"
        if "Type RESET-NOW" in prompt: return "no" if decline else "RESET-NOW"
        return "y"
    sess = ts.Session(elm, log, bundle, ts.AttemptJournal(path.parent / "journal.jsonl"), core,
                      ask=ask, emit=lambda *a: None, sleep=lambda *a: None, clock=Clock())
    rc = ts.run_l1_reset_now(sess)
    log.close()
    return rc, sess.outcomes, timeline
with tempfile.TemporaryDirectory() as d:
    p = pathlib.Path(d)
    rc, out, timeline = run(p/"first")
    assert rc == 0, (rc, out)
    assert out["persistence"] == "adapted after ignition cycle", out
    writes = [f for kind,f in timeline if kind == "write"]
    assert writes.count("31017014") == 1
    i = next(i for i, (kind, f) in enumerate(timeline) if kind == "write" and f.startswith("2702"))
    assert timeline[i+1] == ("write", "31017014"), timeline
    rc, out, timeline = run(p/"second")
    assert rc != 0
    assert not any(kind == "write" for kind,f in timeline)
with tempfile.TemporaryDirectory() as d:
    rc, out, timeline = run(pathlib.Path(d)/"refused", refusal=0x33)
    assert rc == 1 and out["reset_denied_by_security"] is True, (rc,out)
with tempfile.TemporaryDirectory() as d:
    rc, out, timeline = run(pathlib.Path(d)/"declined", decline=True)
    assert rc == 2 and not any(kind == "write" for kind,f in timeline), (rc,timeline)
print("Level-1 repair: consent, successful persistence, no intervening read, refused reset and journal replay passed")
