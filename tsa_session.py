"""Owner-guided, single-attempt shift-force adaptation reset and verification.
Public derivative of the successful November 26 workflow.
No higher-level access, programming operations or automatic fault clearing.
"""
import datetime
import json
import os
import re
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from tsa_analysis import STATUS_30174, assess_firmware, parse_dtcs, summary, value_hex
from tsa_reset_evidence import RecoveryTrace
import tsa_security_access

TOOL_VERSION = "0.1.0"
CAPTURE_SCHEMA = 1
ONE_SHOT = {"session_03": "1003", "seed_request": "2701", "reset_start": "31017014"}
RESULT_POLL_FRAME = "31037014"
ONCE_EVER = frozenset({"seed_request", "send_key", "reset_start"})
UNRESOLVED_OUTCOMES = frozenset({"uncertain", "no_reply", "pending_unresolved", "unexpected", None})
TIMEOUTS = {"session_03": 5.0, "seed_request": 5.0, "send_key": 5.0, "reset_start": 5.0, "result_poll": 3.0}
# Engine ECU 0xD5 returns a two-byte level-1 seed (67 01 S0 S1). A reply of
# any other length is malformed and must not be read as access state (e.g. an
# all-zero 1- or 3-byte reply is NOT "already unlocked").
D5_SEED_LEN = 2
RESULT_POLL_INTERVAL = 1.0
RESULT_POLL_COUNT = 60
RELEARN_POLL_INTERVAL = 5.0
RELEARN_POLL_COUNT = 48            # 4 minutes of idling at most
NOT_ADAPTED_READS = 3
IGNITION_OFF_SECONDS = 65          # TB205 requires at least 60
# ISO 14229-2's default S3 (session timeout) is 5 s; this ECU's value is unknown.
# A longer silence means the extended session may have ended without notice.
SESSION_SILENCE_LIMIT = 4.5


class Cancelled(Exception):
    """The owner declined or interrupted; finish the bundle with what exists."""


# --------------------------------------------------------------------------- #
#  Durable attempt journal
# --------------------------------------------------------------------------- #

class AttemptRefused(Exception):
    """The journal declined to reserve a one-shot operation."""


class AttemptJournal:
    """Append-only, fsynced before each send, so a crash cannot hide an attempt.

    A torn or unreadable line blocks the once-ever operations instead of being
    skipped. The tool never edits or deletes this file.
    """

    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def _locked(self):
        with self.path.open("a+b") as fh:
            if os.name == "nt":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield fh
                finally:
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                yield fh

    @staticmethod
    def _read(fh):
        fh.seek(0)
        entries, corrupt = [], False
        for line in fh:
            try:
                entry = json.loads(line.decode("utf-8"))
                if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                    raise ValueError("invalid journal entry")
                entries.append(entry)
            except ValueError:
                corrupt = True
        return entries, corrupt

    @staticmethod
    def _write(fh, entry):
        entry["ts"] = datetime.datetime.now().isoformat(timespec="milliseconds")
        fh.seek(0, os.SEEK_END)
        fh.write((json.dumps(entry) + "\n").encode("utf-8"))
        fh.flush()
        os.fsync(fh.fileno())

    def _append(self, entry):
        with self._locked() as fh:
            self._write(fh, entry)

    def intent(self, op, frame, visit):
        attempt = uuid.uuid4().hex
        with self._locked() as fh:
            refused = self._refusal(op, *self._read(fh))
            if refused:
                raise AttemptRefused(refused)
            self._write(fh, {"event": "intent", "id": attempt, "op": op,
                             "frame": frame, "visit": visit})
        return attempt

    def result(self, attempt, outcome, payload_hex=None):
        self._append({"event": "result", "id": attempt, "outcome": outcome,
                      "payload_hex": payload_hex})

    def acknowledge(self, attempt):
        self._append({"event": "ack", "id": attempt})

    @staticmethod
    def _outcomes(entries):
        results = {e["id"]: e.get("outcome") for e in entries
                   if e.get("event") == "result"}
        return [(e, results.get(e["id"])) for e in entries
                if e.get("event") == "intent"]

    def refusal(self, op):
        """Why `op` may not be sent again, or None."""
        with self._locked() as fh:
            return self._refusal(op, *self._read(fh))

    def _refusal(self, op, entries, corrupt):
        if op not in ONCE_EVER:
            return None
        if corrupt:
            return f"journal {self.path} has an unreadable entry"
        for entry, outcome in self._outcomes(entries):
            if entry.get("op") == op and outcome != "not_sent":
                return (f"{op} was already attempted at {entry.get('ts')} "
                        f"(outcome: {outcome or 'unfinished'})")
        return None

    def unresolved(self):
        """Attempts whose effect is unknown and not yet acknowledged."""
        with self._locked() as fh:
            entries, _ = self._read(fh)
        acked = {e["id"] for e in entries if e.get("event") == "ack"}
        return [e for e, outcome in self._outcomes(entries)
                if outcome in UNRESOLVED_OUTCOMES and e["id"] not in acked]


# --------------------------------------------------------------------------- #
#  Capture bundle
# --------------------------------------------------------------------------- #

class CaptureBundle:
    """One directory per visit, flushed after every exchange."""

    def __init__(self, root, manifest):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=False)
        (self.root / "snapshots").mkdir()
        self.manifest = dict(manifest, capture_schema=CAPTURE_SCHEMA,
                             tool_version=TOOL_VERSION, commit=_build_commit(),
                             stages=[], status="running",
                             created=_now())
        self.phase = "startup"
        self._lock = threading.Lock()
        self._save_manifest()

    @staticmethod
    def _atomic(path, text):
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def _save_manifest(self):
        self._atomic(self.root / "manifest.json", json.dumps(self.manifest, indent=2))

    def update(self, **fields):
        with self._lock:
            self.manifest.update(fields)
            self._save_manifest()

    def stage(self, name, owner_state=None):
        with self._lock:
            self.phase = name
            self.manifest["stages"].append({"stage": name, "started": _now(),
                                            "owner_state": owner_state})
            self._save_manifest()

    def exchange(self, record):
        with self._lock:
            record = dict(record, phase=self.phase)
            with open(self.root / "exchanges.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def snapshot(self, name, data):
        """Earlier observations are never overwritten by later ones."""
        path = self.root / "snapshots" / f"{name}.json"
        if path.exists():
            raise ValueError(f"snapshot {name} already exists")
        self._atomic(path, json.dumps(data, indent=2))

    def finalize(self, status, text, questions, outcomes):
        self._atomic(self.root / "questions.json", json.dumps(questions, indent=2))
        self._atomic(self.root / "outcomes.json", json.dumps(outcomes, indent=2))
        self._atomic(self.root / "summary.txt", text + "\n")
        self.update(status=status, finished=_now())


def _build_commit():
    """Commit recorded by tools/build_package.py; absent in a source checkout."""
    try:
        return Path(__file__).with_name("BUILD_COMMIT").read_text(encoding="ascii").strip()
    except OSError:
        return None


def _now():
    return datetime.datetime.now().isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------- #
#  Session flow
# --------------------------------------------------------------------------- #

class Session:
    def __init__(self, elm, log, bundle, journal, core, ask=None, emit=print,
                 sleep=None, clock=None):
        self.elm, self.log, self.bundle, self.journal = elm, log, bundle, journal
        self.core = core
        self.ask = ask or input
        self.emit = emit
        self.sleep = sleep or time.sleep
        self.clock = clock or time.monotonic
        self.visit = uuid.uuid4().hex[:12]
        self.outcomes = {}
        self.baseline = None
        self.firmware = None
        self.seed = {"status": "not requested"}
        self.seed_bytes = None                       # raw 27 01 seed, private; used only to compute the D5 key
        self.security = {"status": "not needed"}     # key state; armed for D5 on a non-zero seed (resolve_access)
        self.session = {"status": "not attempted"}
        self.left_session = False
        self.in_changing_stage = False
        elm.on_exchange = bundle.exchange

    def yes(self, prompt):
        try:
            return self.ask(prompt + " [y/N] ").strip().lower() in ("y", "yes")
        except EOFError as e:
            raise Cancelled("input closed") from e

    def typed(self, prompt, word):
        try:
            return self.ask(f"{prompt}\nType {word} to continue: ").strip() == word
        except EOFError as e:
            raise Cancelled("input closed") from e

    def enter(self, prompt):
        try:
            self.ask(prompt + " Press Enter when done. ")
        except EOFError as e:
            raise Cancelled("input closed") from e

    def uncertain(self):
        return bool(self.elm.link_uncertain or self.outcomes.get("link_uncertain"))


def send_once(s, op, frame=None):
    """Journal first, send exactly once, record the outcome.

    `frame` overrides the fixed ONE_SHOT frame for computed frames (the 27 02
    key), whose bytes are not known until runtime.
    """
    frame = ONE_SHOT[op] if frame is None else frame
    try:
        attempt = s.journal.intent(op, frame, s.visit)
    except AttemptRefused as e:
        return {"outcome": "refused", "detail": str(e), "payload": None, "nrc": None}
    try:
        result = s.elm.exchange_once(frame, timeout=TIMEOUTS[op], attempt=attempt)
    except KeyboardInterrupt:
        s.journal.result(attempt, "uncertain")
        s.outcomes["link_uncertain"] = True
        raise
    s.journal.result(attempt, result["outcome"], result.get("payload_hex"))
    if result["outcome"] in UNRESOLVED_OUTCOMES:
        s.outcomes["link_uncertain"] = True
    return result


def _read_dtcs(elm):
    """Read D5 fault records. This ECU rejects the 0xFF status mask (NRC 0x31);
    fall back to the 0x08 confirmedDTC mask, which it accepts. Both are reads."""
    dtc = elm.obd("1902FF", timeout=4)
    if dtc.get("negative"):
        dtc = elm.obd("190208", timeout=4)
    out = parse_dtcs(dtc.get("bytes"))
    if not dtc.get("bytes"):
        out["detail"] = dtc.get("status")
    return out


# Only these identification DIDs are needed off the baseline: VIN and serial for
# the ECU-identity check. The baseline keeps the full sweep for the report.
_RECOVERY_IDENT_DIDS = ("F190", "F18C")


def read_snapshot(s, minimal=False):
    """Read a snapshot. `minimal` reads only what the recovery gates and the
    identity/persistence checks consume (VIN, serial, shift-force status, fault
    records), so the engine-off critical path stays short and the ECU is far
    less likely to time out before the clear and reset. The full baseline sweep
    (every IDENT_DID, calibration discovery) is kept for the report only."""
    core, elm = s.core, s.elm
    if minimal:
        names = dict(core.IDENT_DIDS)
        ident = {}
        for did in _RECOVERY_IDENT_DIDS:
            res = core.parse_rdbi(did, elm.obd(f"22{did}", timeout=4))
            res["name"] = names.get(did, did)
            ident[did] = res
            s.log.event("INFO", f"22 {did} ({res['name']}) -> {res['status']}")
        snap = {"identification": ident,
                "shift_force_status_did": core.read_shift_force_status(elm, s.log)}
    else:
        snap = {"identification": core.read_identification(elm, s.log),
                "shift_force_status_did": core.read_shift_force_status(elm, s.log),
                "tsa_diagnostics": core.read_tsa_diagnostics(elm, s.log)}
    snap["uds_dtcs"] = _read_dtcs(elm)
    return snap


def _status_value(snapshot):
    return value_hex((snapshot or {}).get("shift_force_status_did"))


def stage_discovery(s):
    core, elm = s.core, s.elm
    s.bundle.stage("adapter_trust")
    if not core.phase0(elm, s.log):
        s.outcomes["adapter_trust"] = "failed"
        s.emit("The adapter failed the multi-frame trust test. Stopping before any ECU request.")
        return False
    s.outcomes["adapter_trust"] = "passed"
    s.bundle.update(adapter=elm.at("ATI"), battery=elm.at("ATRV"))

    s.bundle.stage("discovery")
    proto, req, resp = core.CONFIRMED_DIAG_ECU
    s.bundle.update(protocol=proto, request_id=req, response_id=resp)
    functional = {}
    elm.set_addressing(proto, "DB33F1", None)
    for frame in ("0100", "0904"):
        reply = elm.obd(frame, timeout=4)
        functional[frame] = {"raw": reply.get("raw", []), "status": reply.get("status"),
                             "note": "several ECUs may answer; raw lines are the evidence"}
    elm.set_addressing(proto, req, resp)
    alive = elm.obd("0100", timeout=4)
    calibration = core.read_calibration_discovery(elm, s.log, req, resp)
    cvn = elm.obd("0906", timeout=4)
    default_session = elm.obd("1001", timeout=4)
    elm.obd("3E00", timeout=2)
    elm.start_keepalive()

    s.bundle.stage("baseline")
    baseline = read_snapshot(s)
    baseline.update(
        protocol=proto, req_id=req, resp_id=resp, calibration_discovery=calibration,
        functional_discovery=functional,
        physical_0100={"raw": alive.get("raw", []), "status": alive.get("status")},
        cvn={"payload_hex": cvn["bytes"].hex() if cvn.get("bytes") else None,
             "status": cvn.get("status"), "raw": cvn.get("raw", [])},
        default_session={"raw": default_session.get("raw", []),
                         "ok": bool(default_session.get("ok"))})
    s.baseline = baseline
    s.bundle.snapshot("baseline", baseline)
    s.firmware = assess_firmware(baseline)
    s.bundle.snapshot("firmware_check", s.firmware)
    s.outcomes["firmware_check"] = s.firmware["verdict"]
    s.emit("\nFIRMWARE CHECK: " + s.firmware["verdict"].upper())
    for line in s.firmware["reasons"]:
        s.emit("  " + line)
    s.emit("  Limit: " + s.firmware["limit"])
    return True



def stage_session(s):
    """10 03 once, compare reads, and work out the access position."""
    s.bundle.stage("extended_session", owner_state="ignition on, engine off, neutral, stationary")
    result = send_once(s, "session_03")
    payload = result.get("payload")
    accepted = (result["outcome"] == "positive" and payload
                and payload[:2] == b"\x50\x03" and len(payload) in (2, 6))
    s.session = {"status": "accepted" if accepted else result["outcome"],
                 "payload_hex": result.get("payload_hex"), "nrc": result.get("nrc_hex"),
                 "elapsed_ms": result.get("elapsed_ms")}
    s.bundle.snapshot("session_03", s.session)
    s.outcomes["session_03"] = s.session["status"]
    if not accepted:
        s.emit(f"Extended session not established: {result['outcome']} "
               f"{result.get('nrc_hex') or ''}".rstrip())
        return False
    s.elm.hold_session()
    s.emit("Extended session accepted. Reading identity, status and faults again.")
    s.bundle.stage("session_comparison")
    s.bundle.snapshot("after_session_03", read_snapshot(s, minimal=True))
    return True


def _recovery_status(snapshot):
    value = _status_value(snapshot)
    detail = f"DID 0302 = {value or 'unreadable'}"
    if value == "00aa":
        detail += " (feature unavailable)"
    return value in ("0000", "00ff"), detail


def _ecu_identifier(snapshot, did):
    identification = (snapshot or {}).get("identification", {})
    value = value_hex(identification.get(did))
    if not value:
        return None
    data = bytes.fromhex(value)
    if did == "F190":
        return data if re.fullmatch(rb"[A-Z0-9]{17}", data) else None
    return data if data.strip(b"\x00\xff") else None


def _compare_ecu_identity(baseline, snapshot):
    """Compare the physical ECU's VIN and serial without exposing their values."""
    for did, label in (("F190", "VIN"), ("F18C", "ECU serial")):
        expected = _ecu_identifier(baseline, did)
        if expected is None:
            return False, f"baseline {label} unavailable"
        observed = _ecu_identifier(snapshot, did)
        if observed is None:
            return False, f"current {label} unavailable"
        if observed != expected:
            return False, f"{label} differs from baseline"
    return True, "VIN and ECU serial match the baseline"


def _stop_if_snapshot_invalid(s, snapshot, before):
    valid, detail = _compare_ecu_identity(s.baseline, snapshot)
    if valid:
        valid, detail = _recovery_status(snapshot)
    if valid:
        return False
    s.outcomes["recovery"] = f"stopped before {before}: {detail}"
    s.emit(f"Stopping before {before}: {detail}.")
    return True



def session_held(s):
    """(held, detail): could the extended session have timed out since 10 03?

    Only the keepalive's answered 3E 00 and other answered requests count. If
    the ECU went quiet for longer than the limit, the clear and reset would
    likely land in the default session and be refused, using up the attempt.
    """
    silence = s.elm.session_silence()
    if silence is None:
        return False, "no extended session is held"
    detail = (f"longest ECU silence {silence:.1f} s since 10 03 "
              f"(limit {SESSION_SILENCE_LIMIT:.1f} s)")
    return silence <= SESSION_SILENCE_LIMIT, detail


def _stop_if_session_lost(s, before):
    held, detail = session_held(s)
    if held:
        return False
    s.outcomes["recovery"] = f"stopped before {before}: session may have expired"
    s.outcomes["session_held"] = detail
    s.emit(f"\nThe extended session may have timed out: {detail}.")
    s.emit("The ECU did not answer the tester-present keepalive often enough "
           "(or it is disabled).")
    s.emit(f"Stopping before {before}. That step was not sent, so it is not used up.")
    return True



def _adaptation_read(s):
    reply = s.elm.obd("220302", timeout=4)
    return reply["bytes"] if reply.get("ok") and reply.get("bytes") else None


def leave_session(s):
    """Return to default once; never a replay of the earlier setup."""
    if s.left_session:
        return
    s.left_session = True
    elm = s.elm
    if s.uncertain():
        s.emit("Session state is uncertain. Switch the ignition off for 10 seconds "
               "before riding or running the tool again.")
        s.outcomes["session_cleanup"] = "uncertain: ignition cycle needed"
    elif s.session["status"] == "accepted":
        try:
            done = elm.obd("1001", timeout=4)
            s.outcomes["session_cleanup"] = "default session" if done.get("ok") else "not confirmed"
        except s.core.LINK_ERRORS as e:
            s.outcomes["session_cleanup"] = f"link error: {e}"
    elm.release_session()
    if s.in_changing_stage:
        s.in_changing_stage = False
        elm.exit_changing_stage()



def _poll_results(s, trace):
    if trace.stage != "awaiting_completion":
        return
    for _ in range(RESULT_POLL_COUNT):
        s.sleep(RESULT_POLL_INTERVAL)
        result = s.elm.exchange_once(RESULT_POLL_FRAME, timeout=TIMEOUTS["result_poll"],
                                     attempt="poll")
        if result["outcome"] in ("positive", "negative"):
            trace.record_routine_reply(result["payload"])
            if trace.stage != "awaiting_completion":
                return
        elif result["outcome"] not in ("no_reply", "pending_unresolved"):
            s.outcomes["link_uncertain"] = True
            trace.record_interruption()
            return
    trace.record_interruption()


def _finish_guidance(s):
    """Consistent close for any exit AFTER the reset completed (Not Adapted read).

    The owner must never be left thinking the reset failed: it is done and locked
    to one attempt, and the manual steps to finish — including the 60-second
    ignition-off that STORES the adaptation — are always stated, tailored to
    whether Adapted was already relearned.
    """
    s.emit("The adaptation reset ALREADY completed (the ECU read Not Adapted); do NOT run it "
           "again — it is locked to one attempt.")
    if s.outcomes.get("relearn") == "adapted":
        s.emit("Adapted was relearned; only persistence across an ignition cycle is unconfirmed. "
               "Switch the ignition OFF for at least 60 seconds, switch on, then run --check to "
               "confirm the status held.")
    else:
        s.emit("Relearn was not confirmed here. Start the engine and idle in neutral (no throttle, "
               "no gear pedal) until it learns, then switch the ignition OFF for at least 60 "
               "seconds to STORE it, switch on, and run --check. Have any remaining fault codes diagnosed "
               "with a supported service tool.")


def _relearn_and_persist(s, trace):
    s.bundle.stage("relearn", owner_state="owner guided: neutral, idle, pedal at rest")
    s.emit("\nRELEARN. Ventilated area, bike stationary, gearbox in NEUTRAL.")
    s.emit("Start the engine and let it idle. Do not rev it. Do not touch the gear pedal.")
    s.enter("Start the engine now.")
    for _ in range(RELEARN_POLL_COUNT):
        s.sleep(RELEARN_POLL_INTERVAL)
        try:
            payload = _adaptation_read(s)
        except s.core.LINK_ERRORS:
            continue
        if payload is None:
            continue
        trace.record_adaptation_reply(payload)
        if trace.stage != "awaiting_adapted":
            break
    s.outcomes["relearn"] = "adapted" if trace.stage == "awaiting_power_cycle" else "not observed"
    if trace.stage != "awaiting_power_cycle":
        s.emit("Adapted status was not observed within the limit. The reset will not be repeated.")
        s.emit("The ECU may still be learning. Keep idling with the pedal untouched, then")
        s.emit("switch the ignition off for at least 60 seconds so the ECU can store it.")
        s.emit("A later --check reads the status again.")
        return False
    s.emit("ECU reports Adapted.")

    leave_session(s)
    s.bundle.stage("power_cycle", owner_state="owner guided: ignition off at least 60 s")
    s.elm.stop_keepalive()
    s.enter("Switch the engine and ignition OFF.")
    off_at = s.clock()
    s.emit(f"Leave the ignition off. Waiting {IGNITION_OFF_SECONDS} seconds...")
    s.sleep(IGNITION_OFF_SECONDS)
    s.enter("Switch the ignition ON. Leave the engine off.")
    off_seconds = s.clock() - off_at
    trace.record_power_cycle(off_seconds=off_seconds)
    s.outcomes["ignition_off_seconds"] = round(off_seconds, 1)
    s.outcomes["ignition_cycle_owner_confirmed"] = True

    s.bundle.stage("persistence_check")
    proto, req, resp = s.core.CONFIRMED_DIAG_ECU
    if not s.elm.reconnect():
        s.outcomes["persistence"] = "not observed: adapter did not reconnect"
        _finish_guidance(s)
        return False
    s.elm.set_addressing(proto, req, resp)
    final = read_snapshot(s, minimal=True)
    s.bundle.snapshot("final", final)
    same_ecu, detail = _compare_ecu_identity(s.baseline, final)
    if not same_ecu:
        s.outcomes["persistence"] = f"not observed: {detail}"
        s.emit(f"Persistence could not be confirmed: {detail}.")
        _finish_guidance(s)
        return False
    payload = bytes.fromhex("620302" + _status_value(final)) if _status_value(final) else None
    if payload is not None:
        trace.record_adaptation_reply(payload)
    persisted = trace.stage == "persistence_observed"
    s.outcomes["persistence"] = ("adapted after ignition cycle"
                                 if persisted else
                                 f"not observed ({trace.stage})")
    # Report adaptation and returning faults as INDEPENDENT observations. An
    # unreadable DTC response (anything but a parsed 59 02) must NOT be collapsed
    # into "no faults": on this XRT the adaptation can persist while the dash
    # still warns, so a false clean read would hide exactly that. Only a
    # successful read with zero records means fault-free.
    dtc = final.get("uds_dtcs") or {}
    if dtc.get("status") == "ok":
        records = dtc.get("records") if isinstance(dtc.get("records"), list) else []
        faults = [r.get("dtc_hex") for r in records if isinstance(r, dict)]
        trace.record_returning_faults(faults)
        s.outcomes["returning_faults"] = faults
        if faults:
            s.emit("Fault records are present after recovery: " + ", ".join(map(str, faults)))
            s.emit("They are reported, not cleared. The reset will not be repeated.")
    else:
        s.outcomes["returning_faults"] = f"unknown: DTC read {dtc.get('status', 'failed')}"
        s.emit(f"Returning faults UNKNOWN: the post-cycle DTC read did not succeed "
               f"({dtc.get('status', 'failed')}). This is reported separately from the "
               "adaptation result above; it does not mean no faults are present.")
    return persisted



def build_questions(s):
    baseline = s.baseline or {}
    cal = baseline.get("calibration_discovery") or {}
    status = _status_value(baseline)
    dtcs = baseline.get("uds_dtcs") or {}
    items = [
        ("d5_calibration", "Does D5 answer calibration discovery?",
         cal.get("status") not in (None, "no reply"), cal.get("status")),
        ("firmware_match", "Does the installed firmware match image 30174?",
         (s.firmware or {}).get("verdict") in ("matched", "different"),
         (s.firmware or {}).get("verdict")),
        ("adaptation_status", "What is the adaptation status before intervention?",
         status is not None, status),
        ("fault_records", "Which fault records are present?",
         dtcs.get("status") == "ok", dtcs.get("status")),
        ("session_03", "Does D5 accept 10 03?",
         s.session["status"] in ("accepted", "negative"), s.session["status"]),
        ("security_required", "Does the ECU ask for security access?",
         s.seed["status"] in ("seed received", "rejected"), s.seed),
        ("security_unlock", "Does the computed key unlock the ECU (67 02)?",
         "security_unlock" in s.outcomes, s.outcomes.get("security_unlock")),
        ("reset_access", "Is RID 7014 accepted?",
         "reset_start" in s.outcomes, s.outcomes.get("reset_start")),
        ("completion", "Does the routine report completion?",
         "routine" in s.outcomes, s.outcomes.get("routine")),
        ("persistence", "Does adaptation survive an ignition cycle?",
         "persistence" in s.outcomes, s.outcomes.get("persistence")),
    ]
    return [{"id": i, "question": q, "answered": bool(a), "answer": v} for i, q, a, v in items]


def _milestone_and_next(out):
    """(last-confirmed milestone, next applicable step) for the owner summary.

    Works from the guided reset outcomes, including after an interruption,
    and never suggests a road check unless persistence actually
    held. Once the reset milestone is set it always carries "do not repeat",
    mirroring the inline exit guidance.
    """
    persistence = out.get("persistence", "")
    reset_done = "reset_milestone" in out or out.get("not_adapted_read") is True
    relearned = out.get("relearn") == "adapted"
    if isinstance(persistence, str) and persistence.startswith("adapted after"):
        return ("Adaptation persisted across the ignition cycle; the reset is complete.",
                "Next: ride and confirm TSA works on a safe road. (If a dash warning remains "
                "with zero faults because gear adaptation is also incomplete, exercising the "
                "gears under load may be required; stop and run --check if shifting is abnormal "
                "or any fault returns. ECU readings alone do not prove TSA works.)")
    if reset_done and relearned:
        return ("Reset completed and Adapted was relearned; persistence across an ignition "
                "cycle was NOT confirmed.",
                "Next: switch the ignition OFF for at least 60 s, switch on, then run --check to "
                "confirm it held. Do NOT repeat the reset (it is one-shot).")
    if reset_done:
        return ("Reset completed (ECU read Not Adapted); relearn was NOT confirmed.",
                "Next: idle in neutral to relearn, ignition OFF at least 60 s to store it, then "
                "run --check. Do NOT repeat the reset (it is one-shot).")
    reset_start = out.get("reset_start")
    if reset_start == "positive":
        return ("The reset routine started but Not Adapted was not read back.",
                "Next: do NOT repeat it (it is one-shot). Run --check to read the current state.")
    if reset_start is not None:
        return (f"The reset was attempted but not confirmed ({reset_start}).",
                "Next: do NOT repeat it (it is one-shot). Switch the ignition off for 10 s, then "
                "run --check to read the current state.")
    return ("No ECU-changing step was confirmed; the read-only baseline was captured.",
            "Next: nothing to finish. --check re-reads the ECU state at any time.")


def owner_summary(s, status):
    out = s.outcomes
    lines = [f"TSA BIKE SESSION: {status}", ""]
    if s.baseline:
        lines += [summary(s.baseline, guided=True), ""]
    if s.firmware:
        lines.append("Firmware check: " + s.firmware["verdict"])
    labels = (("Adapter trust test", "adapter_trust"), ("Extended session", "session_03"),
              ("Recovery", "recovery"), ("Security unlock", "security_unlock"),
              ("Reset start", "reset_start"),
              # grant -> reset REPLY round-trip (sampled after the exchange returns,
              # so it includes the ECU's own response time), not a pure send delay.
              ("Grant→reset reply (s, incl. response)", "reset_after_grant_seconds"),
              ("Routine stage", "routine"),
              ("Not Adapted read back", "not_adapted_read"),
              ("Relearn", "relearn"),
              ("Persistence", "persistence"), ("Returning faults", "returning_faults"),
              ("Session cleanup", "session_cleanup"))
    lines += [f"{label}: {out[key]}" for label, key in labels if key in out]
    lines.append(f"Seed request: {s.seed['status']}")
    if s.uncertain():
        lines.append("WARNING: at least one exchange had an unknown result. Nothing was resent.")
    milestone, next_step = _milestone_and_next(out)
    lines += ["", "Last confirmed: " + milestone, next_step,
              "This bundle holds your VIN, ECU serial and diagnostic exchanges. Keep it private."]
    return "\n".join(lines)


def _check_unresolved(s):
    pending = s.journal.unresolved()
    if not pending:
        return
    ops = ", ".join(sorted({e.get("op", "?") for e in pending}))
    s.emit(f"An earlier run left a request with an unknown result: {ops}.")
    s.emit("It may have taken effect. It will NOT be replayed automatically.")
    if not s.yes("Has the ignition been off for at least 10 seconds since then?"):
        raise Cancelled("earlier uncertain attempt not acknowledged")
    for entry in pending:
        s.journal.acknowledge(entry["id"])


def _l1_unlock_now(s):
    """Open SecurityAccess level 1 with NO ECU read between the 67 02 grant and
    the caller's next send, so the caller can issue the reset immediately.

    Returns (ok, detail). Sends one 27 01; on a non-zero seed it computes the
    pinned level-1 key offline (K=0x4B48) and sends one 27 02, requiring 67 02.
    An all-zero seed means the ECU is already unlocked and no key is sent. D5
    refuses ReadDataByIdentifier with 0x22 while a 27 01 seed is pending, so this
    deliberately reads nothing between the seed and the key."""
    result = send_once(s, "seed_request")
    payload = result.get("payload")
    if not (result["outcome"] == "positive" and payload and payload[:2] == b"\x67\x01"
            and len(payload) - 2 == D5_SEED_LEN):
        return False, ("seed request did not return a 2-byte 67 01 seed: "
                       f"{result.get('nrc_hex') or result['outcome']}")
    seed = payload[2:]
    s.seed_bytes = seed
    s.seed = {"status": "seed received"}
    s.bundle.snapshot("l1_seed", {"seed_hex": seed.hex(), "private": True,
                                  "all_zero": not any(seed)})
    if not any(seed):
        s.outcomes["security_unlock"] = "already unlocked"
        s.outcomes["l1_unlock"] = "already unlocked (all-zero seed)"
        return True, "all-zero seed (already unlocked); no key sent"
    frame = tsa_security_access.d5_key_frame(tsa_security_access.d5_security_access_key(seed))
    granted = send_once(s, "send_key", frame=frame)
    ok = granted["outcome"] == "positive" and granted.get("payload") == b"\x67\x02"
    s.outcomes["l1_unlock"] = "granted" if ok else (granted.get("nrc_hex") or granted["outcome"])
    s.outcomes["security_unlock"] = s.outcomes["l1_unlock"]
    s.bundle.snapshot("l1_unlock", {"outcome": s.outcomes["l1_unlock"], "granted": ok})
    if not ok:
        return False, f"level-1 key not accepted: {s.outcomes['l1_unlock']}"
    return True, "granted (67 02)"


def _l1_reset_now_sequence(s, trace):
    """Unlock level 1, then send 31 01 70 14 with nothing in between. Returns True
    only when the reset was accepted AND relearn + ignition-cycle persistence
    were verified; False otherwise (the status/outcomes record which case)."""
    with s.elm.reset_sequence_lock():
        ok, detail = _l1_unlock_now(s)
        if not ok:
            s.outcomes["l1_reset_now"] = f"unlock failed: {detail}"
            s.emit(f"Level-1 unlock did not complete: {detail}. The reset was NOT sent.")
            return False
        s.emit(f"Level-1 access: {detail}.")
        if _stop_if_session_lost(s, "the immediate reset"):
            return False
        # The whole point: issue 31 01 70 14 with NOTHING between it and the grant.
        grant_at = s.clock()
        s.bundle.stage("adaptation_reset_immediate")
        trace.record_attempt()
        started = send_once(s, "reset_start")
    # Sampled AFTER the exchange returns, so this is the grant -> reset-REPLY
    # round-trip (it includes the ECU's own response time), not a pure send delay.
    s.outcomes["reset_after_grant_seconds"] = round(s.clock() - grant_at, 3)
    if started["outcome"] in ("positive", "negative"):
        trace.record_routine_reply(started["payload"])
    else:
        trace.record_interruption()
    s.outcomes["reset_start"] = started.get("nrc_hex") or started["outcome"]
    if started.get("nrc") == 0x33:
        s.outcomes["reset_denied_by_security"] = True
        s.outcomes["l1_reset_now"] = "refused at level 1; cause undetermined"
        s.emit("Reset refused. Do not retry or seek higher access. Consult a qualified technician.")
        return False
    if started["outcome"] != "positive" or (started.get("payload") or b"")[:1] != b"\x71":
        s.outcomes["l1_reset_now"] = f"inconclusive: {s.outcomes['reset_start']}"
        s.emit(f"Reset did not return 71 01 70 14: {s.outcomes['reset_start']}. "
               "Not retried; the result is inconclusive.")
        return False
    s.outcomes["l1_reset_now"] = "accepted at level 1"
    s.emit("Reset accepted at level 1.")
    _poll_results(s, trace)
    s.outcomes["routine"] = trace.stage
    if trace.stage != "awaiting_not_adapted":
        s.emit(f"Reset reply seen but the routine did not settle: stage {trace.stage}. "
               "Stopping before relearn.")
        return False
    for _ in range(NOT_ADAPTED_READS):
        payload = _adaptation_read(s)
        if payload is not None:
            trace.record_adaptation_reply(payload)
            break
    s.outcomes["not_adapted_read"] = trace.stage == "awaiting_adapted"
    if trace.stage != "awaiting_adapted":
        s.emit("Routine finished, but Not Adapted was not read back. Stopping before relearn.")
        return False
    s.outcomes["reset_milestone"] = "completed: ECU read Not Adapted (do not repeat)"
    s.emit("Reset finished and the ECU reports Not Adapted.")
    if _status_value(s.baseline) is not None:
        leave_session(s)
    return _relearn_and_persist(s, trace)


def run_l1_reset_now(s):
    """Guided one-attempt level-1 shift-force adaptation reset. NOT read-only:
    opens extended session 10 03, unlocks SecurityAccess level 1, and sends
    31 01 70 14 immediately after the 67 02 grant with no intervening read or
    clear so the level-1 grant does not time out. When accepted, guides idle
    relearning and verifies persistence across an ignition cycle. Returns 0 on
    confirmed persistence, 1 on failure/inconclusive, 2 on cancellation."""
    rc, status = 0, "completed"
    trace = RecoveryTrace()
    try:
        _check_unresolved(s)
        if not stage_discovery(s):
            rc, status = 1, "adapter untrusted"
            raise Cancelled("adapter failed the trust test")
        # Validate identity + adaptation status BEFORE offering the changing op.
        base_ok, base_detail = _compare_ecu_identity(s.baseline, s.baseline)
        if base_ok:
            base_ok, base_detail = _recovery_status(s.baseline)
        if not base_ok:
            s.outcomes["l1_reset_now"] = f"blocked: baseline incomplete ({base_detail})"
            s.emit(f"Baseline is incomplete ({base_detail}); the reset is NOT offered. "
                   "Re-run --check and retry once the ECU reads cleanly.")
            raise Cancelled("baseline incomplete")
        s.emit("\nGUIDED LEVEL-1 SHIFT-FORCE ADAPTATION RESET. This is NOT read-only. It will:")
        s.emit("  1. open an extended diagnostic session (10 03);")
        s.emit("  2. unlock SecurityAccess level 1 (27 01 seed, then the computed 27 02 key);")
        s.emit("  3. send the shift-force adaptation reset (31 01 70 14) immediately after the")
        s.emit("     grant, with no intervening read or clear so level-1 access does not time out;")
        s.emit("  4. guide idle relearning and verify persistence across an ignition-off cycle.")
        s.emit("It sends only level-1 frames: no programming context, no higher-level key,")
        s.emit("no flashing, no fault clearing, and no gear-adaptation reset.")
        s.emit("This changes adaptation state. It is not a substitute for repairing the sensor or wiring.")
        if s.firmware["verdict"] == "different":
            raise Cancelled("firmware identifiers differ")
        if s.firmware["verdict"] == "inconclusive" and not s.typed(
                "Firmware identity inconclusive. Proceed only on the confirmed 2018 XRT model at your own risk.", "UNVERIFIED"):
            raise Cancelled("firmware unverified")
        if not s.yes("Is this a 2018 Tiger 1200 XRT with the underlying hardware fault repaired, engine off and stable battery supply?"):
            raise Cancelled("compatibility or physical prerequisites not confirmed")
        for op in ONCE_EVER:
            reason = s.journal.refusal(op)
            if reason:
                raise Cancelled(reason)
        if not s.typed("Proceed with the guided level-1 shift-force adaptation reset?", "RESET-NOW"):
            s.outcomes["l1_reset_now"] = "declined by owner"
            raise Cancelled("owner declined")
        s.elm.enter_changing_stage()
        s.in_changing_stage = True
        if not stage_session(s):
            s.emit("Extended session not established; the reset would be refused. Stopping.")
            s.outcomes["l1_reset_now"] = "skipped: no extended session"
            raise Cancelled("no extended session")
        in_session = json.loads((s.bundle.root / "snapshots" / "after_session_03.json").read_text(encoding="utf-8"))
        if _stop_if_snapshot_invalid(s, in_session, "the reset"):
            raise Cancelled("ECU identity or status changed")
        if _stop_if_session_lost(s, "the immediate reset"):
            raise Cancelled("session lost")
        s.outcomes["l1_reset_now_complete"] = _l1_reset_now_sequence(s, trace)
    except Cancelled as e:
        rc, status = 2, f"cancelled: {e}"
    except KeyboardInterrupt:
        rc, status = 2, "interrupted by owner"
        s.outcomes["link_uncertain"] = True
    except s.core.SafetyError as e:
        rc, status = 1, f"blocked by guard: {e}"
    except s.core.LINK_ERRORS as e:
        rc, status = 1, f"connection error: {e}"
        s.outcomes["link_uncertain"] = True
    finally:
        try:
            if s.in_changing_stage:
                leave_session(s)
        except (KeyboardInterrupt, *s.core.LINK_ERRORS):
            s.outcomes["session_cleanup"] = "failed"
    if rc == 0 and s.outcomes.get("l1_reset_now_complete") is not True:
        rc, status = 1, "reset or persistence not confirmed"
    if rc == 0 and s.uncertain():
        rc, status = 1, "completed with an unknown result"
    text = owner_summary(s, status)
    s.bundle.finalize(status, text, build_questions(s), s.outcomes)
    s.emit("\n" + text)
    s.emit(f"\nBundle saved to: {s.bundle.root}")
    return rc


def analyze_bundle(root):
    root = Path(root)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("capture_schema") != CAPTURE_SCHEMA:
        raise ValueError(f"Unsupported capture schema: {manifest.get('capture_schema')!r}")
    lines = [f"Bundle status: {manifest.get('status')}  tool {manifest.get('tool_version')}"]
    if manifest.get("synthetic"):
        lines.append("SYNTHETIC demo data, not a motorcycle measurement.")
    if manifest.get("status") == "running":
        lines.append("This bundle was never finalized; the run stopped abruptly.")
    baseline = root / "snapshots" / "baseline.json"
    if baseline.exists():
        report = json.loads(baseline.read_text(encoding="utf-8"))
        lines += ["", summary(report, guided=True), "",
                  "Firmware check: " + assess_firmware(report)["verdict"]]
    questions = root / "questions.json"
    if questions.exists():
        lines += ["", "Open questions:"]
        lines += ["  " + q["question"] for q in
                  json.loads(questions.read_text(encoding="utf-8")) if not q["answered"]]
    outcomes = root / "outcomes.json"
    if outcomes.exists():
        lines += ["", "Outcomes:"]
        lines += [f"  {k}: {v}" for k, v in
                  json.loads(outcomes.read_text(encoding="utf-8")).items()]
    return "\n".join(lines)

class DemoElm:
    """Scripted replies in the shape of Elm327. Never a bike measurement."""

    VIN = "SYNTHETICVIN00000"

    def __init__(self):
        self.link_uncertain = False
        self.on_exchange = None
        self._proto = "7"
        self.status = "00ff"
        self.relearn_reads = 0
        self.polls = 0
        self.reset_done = False
        # Immediate level-1 reset probe: by default 27 01 returns an all-zero
        # seed (already unlocked) and 31 01 70 14 is accepted. Tests override
        # seed_l1 (a 2-byte seed, keyed with the pinned K=0x4B48) and reset_nrc
        # (e.g. 0x33) to model the non-zero-seed and refused-reset cases.
        self.seed_l1 = None
        self.reset_nrc = None

    @staticmethod
    def _reply(payload=None, status=None):
        negative = bool(payload) and payload[0] == 0x7F
        return {"raw": [payload.hex(" ")] if payload else [], "ok": bool(payload) and not negative,
                "status": status, "bytes": payload, "negative": negative,
                "nrc": payload[2] if negative else None,
                "nrc_name": f"0x{payload[2]:02X}" if negative else None}

    def at(self, cmd, timeout=None):
        return ["ELM327 demo"] if cmd == "ATI" else ["12.8V"] if cmd == "ATRV" else ["OK"]

    def obd(self, frame, timeout=None):
        table = {"0100": b"\x41\x00\xBE\x1F\xA8\x13",
                 "0902": b"\x49\x02\x01" + self.VIN.encode(),
                 "1001": b"\x50\x01\x00\x32\x01\xF4", "3E00": b"\x7E\x00",
                 "22F190": b"\x62\xF1\x90" + self.VIN.encode(),
                 "22F18C": b"\x62\xF1\x8C\x00\x11\x22\x33\x44",
                 "22F1A7": b"\x62\xF1\xA7\x20\x17\x01",
                 "22F1A0": b"\x62\xF1\xA0\x00\x00\x00",
                 "220300": b"\x62\x03\x00\x00\xFF",
                 "220301": b"\x62\x03\x01\x00\xFF",
                 "22013C": b"\x62\x01\x3C\x85"}
        if frame == "220302":
            if self.reset_done and self.status == "0000":
                self.relearn_reads += 1
                if self.relearn_reads > 2:
                    self.status = "00ff"
            return self._reply(bytes.fromhex("620302" + self.status))
        if frame == "1902FF":
            records = b"" if self.reset_done else bytes.fromhex("17020009")
            return self._reply(b"\x59\x02\xFF" + records)
        if frame == "190208":
            records = b"" if self.reset_done else bytes.fromhex("17020008" "17030008")
            return self._reply(b"\x59\x02\x08" + records)
        if frame in table:
            return self._reply(table[frame])
        if frame.startswith("22"):
            return self._reply(b"\x7F\x22\x31")
        return self._reply(None, "NO DATA")

    def exchange_once(self, frame, timeout=5.0, attempt=None):
        if frame == "1003":
            payload = bytes.fromhex("5003003201F4")
        elif frame == "31017014":
            if self.reset_nrc is not None:
                return {"outcome": "negative", "payload": bytes([0x7F, 0x31, self.reset_nrc]),
                        "payload_hex": f"7F31{self.reset_nrc:02X}", "nrc": self.reset_nrc,
                        "nrc_hex": f"0x{self.reset_nrc:02X}", "raw": [], "elapsed_ms": 1,
                        "sent": True}
            payload = bytes.fromhex("71017014")
            self.reset_done, self.status = True, "0000"
        elif frame == "2701":                          # level-1 seed request
            payload = b"\x67\x01" + (self.seed_l1 if self.seed_l1 is not None
                                     else b"\x00\x00")
        elif frame.startswith("2702") and len(frame) == 8:   # level-1 key (2 bytes)
            want = (tsa_security_access.d5_key_frame(
                        tsa_security_access.d5_security_access_key(self.seed_l1))
                    if self.seed_l1 is not None else None)
            if want is not None and frame.upper() == want.upper():
                payload = bytes.fromhex("6702")
            else:
                return {"outcome": "negative", "payload": bytes([0x7F, 0x27, 0x35]),
                        "payload_hex": "7F2735", "nrc": 0x35, "nrc_hex": "0x35",
                        "raw": [], "elapsed_ms": 1, "sent": True}
        elif frame == "31037014":
            self.polls += 1
            payload = bytes.fromhex("7103701480" if self.polls < 3 else "7103701462")
        else:
            raise AssertionError("Unexpected synthetic request")
        return {"outcome": "positive", "payload": payload, "payload_hex": payload.hex(),
                "nrc": None, "nrc_hex": None, "raw": [], "elapsed_ms": 1, "sent": True}

    @contextmanager
    def reset_sequence_lock(self):
        yield

    def set_addressing(self, *args):
        pass

    def start_keepalive(self, interval=None):
        pass

    def stop_keepalive(self):
        pass

    def hold_session(self):
        pass

    def release_session(self):
        pass

    def session_silence(self):
        return 0.0

    def enter_changing_stage(self):
        pass

    def exit_changing_stage(self):
        pass

    def reconnect(self, attempts=3, reopen=True):
        return True

