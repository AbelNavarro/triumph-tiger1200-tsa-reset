#!/usr/bin/env python3
"""Public TSA diagnostics and guided shift-force sensor adaptation reset.
Read-only checks and a separate explicit level-1 repair workflow.
Derived from the original guarded transport and diagnostic implementation.
Raw local reports and logs can contain VIN and ECU serial: do not share them.
"""
import re
import sys
import json
import time
import threading
import argparse
import datetime
from pathlib import Path
from types import MappingProxyType
from tsa_analysis import assess_report, read_report, summary, demo_report, parse_dtcs

# v2: adds "protocol" (6 = 11-bit, 7 = 29-bit)
# v3: UDS identification reads
# v4: UDS fault records, warning-mask reads, read-only TSA DIDs, offline assessment
REPORT_VERSION = 4

# The diagnostic ECU confirmed on the bike: (ELM protocol, ATSH header,
# ATCRA receive filter).
CONFIRMED_DIAG_ECU = ("7", "DAD5F1", "18DAF1D5")

RESET_UNAVAILABLE = "Use the explicit guided --l1-reset-now repair workflow only"

try:
    import serial  # pyserial
except ImportError:
    serial = None  # Offline analysis and --help do not need an adapter library.

LINK_ERRORS = (OSError, serial.SerialException) if serial else (OSError,)


# --------------------------------------------------------------------------- #
#  Logging
# --------------------------------------------------------------------------- #

class SessionLog:
    """Timestamped append-only log, mirrored to stdout and a file on disk."""

    def __init__(self, path, quiet=False):
        self.path = Path(path)
        self.quiet = quiet
        self._fh = open(self.path, "a", encoding="utf-8")
        self.event("LOG", f"session log opened: {self.path}")

    @staticmethod
    def _ts():
        return datetime.datetime.now().isoformat(timespec="milliseconds")

    def _write(self, line):
        self._fh.write(line + "\n")
        self._fh.flush()
        if not self.quiet:
            print(line)

    def event(self, kind, msg):
        self._write(f"[{self._ts()}] {kind:<5} {msg}")

    def tx(self, raw):
        self._write(f"[{self._ts()}] TX    {raw!r}")

    def rx(self, raw):
        self._write(f"[{self._ts()}] RX    {raw!r}")

    def close(self):
        self.event("LOG", "session log closed")
        self._fh.close()


# --------------------------------------------------------------------------- #
#  Safety: transmit allowlist
# --------------------------------------------------------------------------- #

class SafetyError(Exception):
    """Raised when a frame is not permitted, or a precondition is unmet."""


class TxGuard:
    """Default-deny read path and narrowly scoped level-1 repair path."""

    ONE_SHOT_EXACT = frozenset({"1003", "2701", "31017014", "31037014"})
    ONE_SHOT_D5_KEY_RE = re.compile(r"^2702[0-9A-F]{4}$")
    # BEFORE the allowlist, so a future allowlist edit cannot reopen them.
    # Covers UDS (ISO 14229), the KWP2000 equivalents, and OBD modes 04/08.
    ECU_CHANGING_SERVICES = MappingProxyType({
        "04": "OBD clear DTCs",
        "08": "OBD control of on-board system",
        "11": "ECUReset",
        "14": "ClearDiagnosticInformation",
        "27": "SecurityAccess",
        "28": "CommunicationControl",
        "29": "Authentication",
        "2C": "DynamicallyDefineDataIdentifier",
        "2E": "WriteDataByIdentifier",
        "2F": "InputOutputControlByIdentifier",
        "30": "KWP InputOutputControlByLocalIdentifier",
        "31": "RoutineControl / KWP StartRoutineByLocalIdentifier",
        "32": "KWP StopRoutineByLocalIdentifier",
        "33": "KWP RequestRoutineResultsByLocalIdentifier",
        "34": "RequestDownload",
        "35": "RequestUpload",
        "36": "TransferData",
        "37": "RequestTransferExit",
        "38": "RequestFileTransfer / KWP StartRoutineByAddress",
        "39": "KWP StopRoutineByAddress",
        "3A": "KWP RequestRoutineResultsByAddress",
        "3B": "KWP WriteDataByLocalIdentifier",
        "3D": "WriteMemoryByAddress",
        "83": "AccessTimingParameter",
        "84": "SecuredDataTransmission",
        "85": "ControlDTCSetting",
        "86": "ResponseOnEvent",
        "87": "LinkControl",
    })

    # The ONLY frames that may be transmitted, besides 22 xx xx below.
    # All are reads or keep-alives:
    #   01 00         OBD mode 1 PID-support read (bike-alive check, discovery)
    #   03 / 07       OBD stored / pending DTC read
    #   09 02         OBD VIN read (adapter multi-frame trust test)
    #   10 01         UDS DiagnosticSessionControl -> DEFAULT session
    #   10 81         same, suppressPosRsp bit set. ECU 0xD5 answers NRC 0x12,
    #                 which is how the address sweep finds diagnostic modules.
    #   3E 00         UDS TesterPresent (keep-alive)
    # No other session is allowed: every confirmed read works in the default
    # session, and the non-default sessions are what unlock ECU-changing
    # services.
    # 19 02 FF: read engine-ECU DTCs by status mask. No other SID19 request.
    # 09 06: calibration verification number read, captured for later comparison.
    EXACT_ALLOWED = frozenset({"0100", "03", "07", "0902", "0904", "0906", "1001",
                               "1081", "3E00", "1902FF",
                               # read-only ReadDTCInformation (SID 0x19) variants,
                               # added to confirm P1702/P1703 status. All are
                               # reads; 0x19 is not an ECU-changing service.
                               "190A", "1901FF", "190208", "190204", "19022F",
                               "1902AF"})

    # UDS ReadDataByIdentifier, exactly one 2-byte DID: 22 xx xx.
    READ_DID_SERVICE = "22"

    # Adapter commands actually used by this tool (spaces removed, upper case).
    # Excluded on purpose, among others: ATCAF0 (raw frames would bypass the
    # service-byte check), ATPP (writes adapter EEPROM), ATWM / ATSW (periodic
    # wake-up frames), ATBRD (baud change), any ST* (STN raw transmit), and
    # ATSP other than 6/7 (the bus is 500 kbit/s; 250k crashes clone adapters).
    _AT_ALLOWED = re.compile(
        r"^AT(?:Z|I|E0|L0|S1|H1|RV|AR|MA|CAF1|AT[01]|SP[67]|CP18"
        r"|ST[0-9A-F]{2}"
        r"|SH(?:[0-9A-F]{3}|[0-9A-F]{6})"
        r"|CRA(?:[0-9A-F]{3}|[0-9A-F]{8}))$"
    )

    def __init__(self, log):
        self.log = log

    @staticmethod
    def _norm(frame_hex):
        """Uppercase, strip spaces/separators -> contiguous hex string."""
        s = "".join(str(frame_hex).split()).replace(":", "").upper()
        if not s or len(s) % 2 != 0 or any(c not in "0123456789ABCDEF" for c in s):
            raise SafetyError(f"not valid hex: {frame_hex!r}")
        return s

    def assert_tx_allowed(self, frame_hex):
        """
        Raise SafetyError unless the frame is a permitted read. Called before
        EVERY bus transmit. Returns the normalized hex on success.
        """
        f = self._norm(frame_hex)
        svc = f[:2]
        if svc in self.ECU_CHANGING_SERVICES:
            raise SafetyError(f"FORBIDDEN ECU-changing service 0x{svc} "
                              f"({self.ECU_CHANGING_SERVICES[svc]}): {f}")
        if f in self.EXACT_ALLOWED:
            return f
        if svc == self.READ_DID_SERVICE and len(f) == 6:
            return f
        raise SafetyError(f"frame not in read-only allowlist: {f}")

    def assert_oneshot_allowed(self, frame_hex):
        """Only D5 level-1 access used by the shift-force adaptation routine."""
        f = self._norm(frame_hex)
        if f in self.ONE_SHOT_EXACT or self.ONE_SHOT_D5_KEY_RE.fullmatch(f):
            return f
        raise SafetyError(f"frame not in repair allowlist: {f}")

    def assert_at_allowed(self, cmd):
        """Raise SafetyError unless `cmd` is one of the adapter commands this
        tool uses. Returns the command unchanged on success."""
        c = "".join(str(cmd).split()).upper()
        if not self._AT_ALLOWED.match(c):
            raise SafetyError(f"adapter command not in allowlist: {cmd!r}")
        return cmd


# --------------------------------------------------------------------------- #
#  ELM327 adapter wrapper
# --------------------------------------------------------------------------- #

class Elm327:
    PROMPT = b">"

    def __init__(self, port, baud, log, guard, timeout=5.0):
        self.log = log
        self.guard = guard
        self.timeout = timeout
        self.port = port
        self.baud = baud
        self.ser = None
        # serialize ALL port access (command flow + keepalive thread share it)
        self._lock = threading.RLock()
        # remembered state so a reconnect can restore the live context
        self._sh = None            # last ATSH header
        self._cra = None           # last ATCRA receive filter
        self._proto = "6"          # ELM protocol: 6 = 11-bit, 7 = 29-bit (500k)
        self._session_sub = None   # last successful 10xx session subfunction
        # keepalive
        self.ka_enabled = True
        self._ka_interval = 1.5
        self._ka_thread = None
        self._ka_stop = threading.Event()
        self._hold_session = False  # send 3E 00 for a session we cannot replay
        self._session_activity = None  # ECU reply timing while a session is held
        # Changing stage: no reconnect or replay; a lost link stays lost.
        self.changing_stage = False
        self.link_uncertain = False
        self.on_exchange = None     # bundle callback for structured records
        self._open()

    def _open(self):
        """(Re)open the serial port. Caller holds the lock on reconnect."""
        try:
            if self.ser is not None:
                self.ser.close()
        except Exception:
            pass
        # Bluetooth SPP ports often refuse a reopen for a second or two after
        # a close (Windows error 1231 "network location cannot be reached")
        # while the RFCOMM link tears down / re-establishes. Retry with backoff.
        last_err = None
        for attempt in range(1, 7):
            self.log.event("PORT", f"opening {self.port} @ {self.baud}"
                                   + (f" (attempt {attempt})" if attempt > 1 else ""))
            try:
                # write_timeout: a write to a dropped BT link must fail, not
                # block forever.
                self.ser = serial.Serial(self.port, self.baud, timeout=0.2,
                                         write_timeout=2)
                break
            except (OSError, serial.SerialException) as e:
                last_err = e
                self.ser = None
                wait = min(1.0 + attempt, 5.0)
                self.log.event("PORT", f"open failed ({e}); retrying in {wait:.0f}s")
                time.sleep(wait)
        else:
            raise serial.SerialException(
                f"could not open {self.port} after retries: {last_err}")
        time.sleep(0.5)
        self.ser.reset_input_buffer()

    # -- low-level -------------------------------------------------------- #

    def _read_until_prompt(self, timeout=None):
        """Read bytes until the ELM '>' prompt or timeout."""
        timeout = self.timeout if timeout is None else timeout
        deadline = time.time() + timeout
        buf = bytearray()
        while time.time() < deadline:
            chunk = self.ser.read(64)
            if chunk:
                buf.extend(chunk)
                if self.PROMPT in buf:
                    break
            else:
                if buf and buf.rstrip().endswith(b">"):
                    break
        text = buf.decode("ascii", errors="replace")
        self.log.rx(text)
        return text

    @staticmethod
    def _clean(text):
        """Normalize an ELM response into clean, non-empty lines."""
        lines = []
        for raw in text.replace("\r", "\n").split("\n"):
            s = raw.strip()
            if s and s != ">":
                lines.append(s)
        return lines

    def _raw_at(self, cmd, timeout=None):
        """Low-level AT write/read. Caller holds the lock. Guarded here too,
        so reconnect's replayed init cannot skip the AT allowlist."""
        self.guard.assert_at_allowed(cmd)
        self.log.tx(cmd)
        self.ser.reset_input_buffer()
        self.ser.write((cmd + "\r").encode("ascii"))
        return self._clean(self._read_until_prompt(timeout))

    def _raw_write(self, norm):
        """Low-level service write. Caller holds the lock. This is the single
        point where service frames reach the port, so the read-only guard is
        enforced here regardless of the caller."""
        norm = self.guard.assert_tx_allowed(norm)
        self.log.tx(norm)
        self.ser.reset_input_buffer()
        self.ser.write((norm + "\r").encode("ascii"))

    @staticmethod
    def _strip_echo(cmd, lines):
        """If the adapter echoed the command back (echo is back ON, i.e. it
        reset itself and lost our init), drop that line. Returns
        (lines, echoed)."""
        if lines and lines[0].replace(" ", "").upper() == cmd.replace(" ", "").upper():
            return lines[1:], True
        return lines, False

    def at(self, cmd, timeout=None, _retry=True):
        """Send an adapter AT command (never goes on the bus).
        An AT command always gets a reply ('OK', a value, or '?'), so an
        empty reply means the Bluetooth link dropped: reconnect and retry."""
        # check before remembering any header/filter/protocol state
        self.guard.assert_at_allowed(cmd)
        with self._lock:
            parts = cmd.split()
            up = cmd.upper()
            if up.startswith("ATSH") and len(parts) > 1:
                self._sh = parts[-1]
            elif up.startswith("ATCRA"):
                self._cra = parts[-1] if len(parts) > 1 else None
            elif up == "ATAR":
                self._cra = None
            elif up.startswith("ATSP") and len(up) > 4:
                self._proto = up[4:].strip()
            try:
                lines = self._raw_at(cmd, timeout)
            except (OSError, serial.SerialException) as e:
                self.log.event("PORT", f"tx/rx failed on {cmd}: {e}")
                lines = None
            if self.changing_stage:
                _retry = False
                if lines and self._strip_echo(cmd, lines)[1]:
                    self.link_uncertain = True
                    raise serial.SerialException(f"adapter reset itself during {cmd}")
                if not lines:
                    self.link_uncertain = True
            if lines and up not in ("ATZ", "ATE0"):
                lines, echoed = self._strip_echo(cmd, lines)
                if echoed and _retry:
                    self.log.event("PORT", f"echo on {cmd}: adapter reset itself; "
                                           f"re-initialising")
                    if self.reconnect(reopen=False):
                        return self.at(cmd, timeout=timeout, _retry=False)
            if lines:
                return lines
            if not lines and _retry:
                self.log.event("PORT", f"no reply to {cmd}; link looks dropped")
                if self.reconnect():
                    # reconnect already restored ATSH/ATCRA from _sh/_cra
                    return self.at(cmd, timeout=timeout, _retry=False)
            raise serial.SerialException(f"adapter not responding to {cmd}")

    def obd(self, frame_hex, timeout=None, _retry=True):
        """
        Send an application-layer (service) frame.  Passes through the
        read-only guard first; raises SafetyError if not permitted (nothing
        is written to the port in that case).
        On a serial failure (BT drop) it reconnects once and retries; that is
        safe because only reads and keep-alives can reach this point.
        """
        norm = self.guard.assert_tx_allowed(frame_hex)  # may raise
        started = time.time()
        with self._lock:
            try:
                self._raw_write(norm)
                lines = self._clean(self._read_until_prompt(timeout))
            except (OSError, serial.SerialException) as e:
                self.log.event("PORT", f"tx/rx failed on {norm}: {e}")
                self._record("read", norm, started, error=str(e))
                if self.changing_stage:
                    self.link_uncertain = True
                    raise
                if _retry and self.reconnect():
                    return self.obd(frame_hex, timeout=timeout, _retry=False)
                raise
            lines, echoed = self._strip_echo(norm, lines)
            if echoed:
                if self.changing_stage:
                    self.link_uncertain = True
                    self._record("read", norm, started, error="adapter reset itself")
                    raise serial.SerialException(f"adapter reset itself during {norm}")
                # adapter reset itself: restore init for the NEXT command;
                # this frame is not re-sent.
                self.log.event("PORT", f"echo on {norm}: adapter reset itself; "
                                       f"re-initialising (frame not re-sent)")
                self.reconnect(reopen=False)
        res = self._interpret(lines, request_service=int(norm[:2], 16))
        self._record("read", norm, started, result=res)
        # remember a successfully opened session so reconnect can restore it
        if (norm.startswith("10") and res.get("ok") and res["bytes"]
                and len(res["bytes"]) >= 2 and res["bytes"][0] == 0x50
                and res["bytes"][1] in (int(norm[2:], 16), int(norm[2:], 16) & 0x7F)):
            self._session_sub = norm[2:]
        return res

    # -- Exchange recording ------------------------------------------------ #

    D5_HEADER, D5_FILTER = "DAD5F1", "18DAF1D5"

    def _record(self, kind, norm, started, result=None, error=None, attempt=None):
        """Hand one structured exchange to the capture bundle, if any."""
        result = result or {}
        data = result.get("bytes", result.get("payload"))
        self._note_session_activity(started, data)
        if not self.on_exchange:
            return
        self.on_exchange({
            "ts": datetime.datetime.now().isoformat(timespec="milliseconds"),
            "kind": kind, "request": norm, "attempt": attempt,
            "elapsed_ms": int((time.time() - started) * 1000),
            "header": self._sh, "filter": self._cra, "raw": result.get("raw", []),
            "payload_hex": data.hex() if data else None,
            "ok": result.get("ok"), "outcome": result.get("outcome"),
            "nrc": result.get("nrc"), "status": result.get("status"), "error": error})

    def enter_changing_stage(self):
        """Stop automatic recovery, and use a fixed ~1 s adapter wait."""
        self.changing_stage = True
        self.at("ATAT0")
        self.at("ATST FF")

    def exit_changing_stage(self):
        try:
            self.at("ATST 32")
            self.at("ATAT1")
        finally:
            self.changing_stage = False

    def reset_sequence_lock(self):
        return self._lock

    def hold_session(self):
        """Keep a non-default session alive; it is never replayed on reconnect.
        Call it right after the session reply: silence is measured from here."""
        with self._lock:
            self._hold_session = True
            self._session_activity = {"last": time.monotonic(), "longest": 0.0}

    def release_session(self):
        with self._lock:
            self._hold_session = False
            self._session_activity = None

    def _note_session_activity(self, started, data):
        """The ECU's session timer (S3) restarts with each request it answers.
        Record the longest gap between an answer and the next answered request.
        An unanswered request is not assumed to have kept the session."""
        if not data:
            return
        with self._lock:
            act = self._session_activity
            if act is None:
                return
            now = time.monotonic()
            sent = now - max(0.0, time.time() - started)
            act["longest"] = max(act["longest"], sent - act["last"])
            act["last"] = max(act["last"], now)

    def session_silence(self):
        """Longest ECU silence in seconds since hold_session(), counting up to
        now, or None when no session is held."""
        with self._lock:
            act = self._session_activity
            if act is None:
                return None
            return max(act["longest"], time.monotonic() - act["last"])


    def exchange_once(self, frame_hex, timeout=5.0, attempt=None):
        """Send one changing frame to physical D5 and classify what came back.

        Never retries, reconnects or resends. Outcomes:
          not_sent            addressing could not be confirmed; nothing written
          positive / negative a complete matching ECU reply
          pending_unresolved  only "response pending" within the deadline
          no_reply            the adapter reported no data
          uncertain           the link failed; the request may have taken effect
          unexpected          a reply that does not belong to this request
        """
        norm = self.guard.assert_oneshot_allowed(frame_hex)
        service = int(norm[:2], 16)
        started = time.time()
        result = {"request": norm, "outcome": "uncertain", "raw": [], "sent": False,
                  "payload": None, "payload_hex": None, "nrc": None, "nrc_hex": None,
                  "detail": None}
        with self._lock:
            try:
                if self.link_uncertain:
                    result.update(outcome="not_sent", detail="link already uncertain")
                else:
                    self._exchange_locked(norm, service, started + timeout, timeout, result)
            except (OSError, serial.SerialException) as e:
                self.log.event("PORT", f"one-shot failed on {norm}: {e}")
                result.update(outcome="uncertain" if result["sent"] else "not_sent",
                              detail=str(e))
            if result["outcome"] == "uncertain":
                self.link_uncertain = True
            result["elapsed_ms"] = int((time.time() - started) * 1000)
        self.log.event("ONCE", f"{norm} -> {result['outcome']} {result['nrc_hex'] or ''}")
        self._record("one_shot", norm, started, result=result, attempt=attempt,
                     error=result["detail"])
        return result

    def _exchange_locked(self, norm, service, deadline, timeout, result):
        norm = self.guard.assert_oneshot_allowed(norm)
        for cmd in (f"ATSH {self.D5_HEADER}", f"ATCRA {self.D5_FILTER}"):
            if self._raw_at(cmd, timeout=2) != ["OK"]:
                result.update(outcome="not_sent", detail=f"adapter refused {cmd}")
                return
        self._sh, self._cra = self.D5_HEADER, self.D5_FILTER
        data = (norm + "\r").encode("ascii")
        self.log.tx(norm)
        self.ser.reset_input_buffer()
        result["sent"] = True      # set first: a failed write may be partial
        written = self.ser.write(data)
        if written is not None and written != len(data):
            result["detail"] = f"partial write: {written} of {len(data)} bytes"
            return
        text = self._read_until_prompt(timeout)
        lines = self._clean(text)
        result["raw"] = lines
        if self.PROMPT.decode() not in text:
            result["detail"] = "no adapter prompt before the deadline"
            return
        lines, echoed = self._strip_echo(norm, lines)
        if echoed:
            result["detail"] = "adapter reset itself during the request"
            return
        reply = self._interpret(lines, request_service=service)
        if reply["negative"] and reply["nrc"] == 0x78:
            result["outcome"] = "pending_unresolved"
            reply = self._collect_after_prompt(service, deadline, result)
            if reply is None:
                return
        self._classify(reply, service, result)

    def _collect_after_prompt(self, service, deadline, result):
        """Listen passively for the final reply. A bare CR repeats the last
        command, so the CR below is written only after ATMA became the last
        command, and only to stop it. The ECU request is never repeated."""
        self.guard.assert_at_allowed("ATMA")
        self.log.tx("ATMA")
        self.ser.reset_input_buffer()
        self.ser.write(b"ATMA\r")
        buf, final, prompted, seen = bytearray(), None, False, 0
        while time.time() < deadline and final is None and not prompted:
            chunk = self.ser.read(64)
            if not chunk:
                continue
            buf.extend(chunk)
            prompted = self.PROMPT in chunk
            text = buf.decode("ascii", errors="replace").replace("\r", "\n")
            complete = text.split("\n")[:-1]
            fresh, seen = complete[seen:], len(complete)
            for line in fresh:
                reply = self._interpret([line.strip()], request_service=service)
                if reply["bytes"] and not (reply["negative"] and reply["nrc"] == 0x78):
                    final = reply
                    break
        if not prompted:
            self.ser.write(b"\r")
            self._read_until_prompt(2)
        self.log.rx(buf.decode("ascii", errors="replace"))
        result["raw"] = result["raw"] + self._clean(buf.decode("ascii", errors="replace"))
        return final
    @staticmethod
    def _classify(reply, service, result):
        payload = reply["bytes"]
        result["detail"] = reply.get("status")
        if not payload:
            result["outcome"] = "no_reply" if reply.get("status") == "NO DATA" else "uncertain"
            return
        result.update(payload=payload, payload_hex=payload.hex())
        if reply["negative"] and payload[1] == service:
            result.update(outcome="negative", nrc=reply["nrc"],
                          nrc_hex=f"0x{reply['nrc']:02X}")
        elif reply["ok"] and payload[0] == service + 0x40:
            result["outcome"] = "positive"
        else:
            result["outcome"] = "unexpected"

    # -- response handling ------------------------------------------------ #

    ELM_STATUS = {
        "SEARCHING...", "NO DATA", "BUFFER FULL", "CAN ERROR",
        "STOPPED", "UNABLE TO CONNECT", "BUS INIT: ERROR", "?",
    }

    NRC = {
        0x10: "generalReject", 0x11: "serviceNotSupported",
        0x12: "subFunctionNotSupported", 0x22: "conditionsNotCorrect",
        0x31: "requestOutOfRange", 0x33: "securityAccessDenied",
        0x78: "responsePending", 0x7F: "serviceNotSupportedInActiveSession",
    }

    def _interpret(self, lines, request_service=None):
        """
        Turn cleaned ELM lines into a dict:
          {ok, status, data_lines, bytes, negative, nrc, nrc_name}
        'bytes' is the reassembled ISO-TP payload (service id first) when the
        line(s) look like hex data.
        """
        result = {
            "raw": lines, "ok": False, "status": None,
            "bytes": None, "negative": False, "nrc": None, "nrc_name": None,
        }
        # Adapter-level status strings
        for ln in lines:
            up = ln.upper()
            for st in self.ELM_STATUS:
                if up == st or up.startswith(st):
                    # SEARCHING... often precedes real data; keep scanning.
                    if st != "SEARCHING...":
                        result["status"] = st
        if result["status"] and result["status"] != "SEARCHING...":
            return result

        payload = self._reassemble(lines, request_service=request_service)
        if payload is None:
            return result
        result["bytes"] = payload
        if payload[0] == 0x7F and len(payload) != 3:
            result["status"] = "malformed negative response"
            return result
        if len(payload) >= 3 and payload[0] == 0x7F:
            result["negative"] = True
            result["nrc"] = payload[2]
            result["nrc_name"] = self.NRC.get(payload[2], f"0x{payload[2]:02X}")
            self.log.event("NRC",
                           f"negative response svc=0x{payload[1]:02X} "
                           f"nrc=0x{payload[2]:02X} ({result['nrc_name']})")
            return result
        result["ok"] = True
        return result

    def _reassemble(self, lines, request_service=None):
        """
        Reassemble an ISO-TP payload from ELM hex lines.

        With ATH1 (headers on), multi-frame responses are printed as:
            7E8 10 14 <...>      (first frame, total length 0x014)
            7E8 21 <...>         (consecutive frame #1)
            7E8 22 <...>         ...
        Single frame:
            7E8 06 50 01 ...     (single frame, length 0x6)
        We tolerate headers being present or absent.
        """
        frames = []
        source = None
        for ln in lines:
            toks = ln.replace(":", " ").split()
            header = None
            if toks and re.fullmatch(r"[0-9A-Fa-f]{3}|[0-9A-Fa-f]{8}", toks[0]):
                header = toks.pop(0).upper()
            elif (len(toks) >= 5 and toks[0].upper() == "18" and
                  toks[1].upper() in ("DA", "DB") and
                  all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in toks[:4])):
                header = "".join(toks[:4]).upper()
                toks = toks[4:]
            if not toks or not all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in toks):
                continue
            if header:
                expected = getattr(self, "_cra", None)
                sh = getattr(self, "_sh", None)
                if expected is None and sh and re.fullmatch(r"DA[0-9A-F]{2}F1", sh):
                    expected = "18DAF1" + sh[2:4]
                if expected and header != expected.upper():
                    return None
                if source is not None and source != header:
                    return None
                source = header
            elif source is not None:
                return None
            frames.append((header, bytes(int(t, 16) for t in toks)))
        if not frames or len({h for h, _ in frames}) != 1:
            return None
        # Pending messages are complete UDS responses, not ISO-TP fragments.
        # Validate every source above before removing any leading messages.
        pending_service = None
        while frames:
            frame = frames[0][1]
            pending = (frame[1:4] if 4 <= len(frame) <= 8 and frame[0] == 3
                       else frame if len(frame) == 3 else b"")
            if len(pending) != 3 or pending[0] != 0x7F or pending[2] != 0x78:
                break
            if ((request_service is not None and pending[1] != request_service) or
                    (pending_service is not None and pending[1] != pending_service)):
                return None
            pending_service = pending[1]
            frames = frames[1:]
        if not frames:
            # A pending-only transaction is still pending, never success.
            return bytes((0x7F, pending_service, 0x78))
        payload = self._payload_from_frames(frames)
        if pending_service is not None and payload:
            if payload[0] == 0x7F:
                if len(payload) != 3 or payload[1] != pending_service:
                    return None
            elif payload[0] != pending_service + 0x40:
                return None
        return payload

    @staticmethod
    def _payload_from_frames(frames):
        """Reassemble exactly one final message after source/pending checks."""
        first = frames[0][1]
        kind = first[0] >> 4
        if kind == 0:
            size = first[0]
            if len(frames) != 1 or not 1 <= size <= 7 or len(first) < size + 1:
                return None
            return first[1:1 + size]
        if kind != 1:
            # Unframed UDS/OBD payload: never accept orphan CF/FC as payload.
            return first if len(frames) == 1 and kind >= 4 else None
        if len(first) != 8:
            return None
        total = ((first[0] & 15) << 8) | first[1]
        if total <= 7:
            return None
        data = bytearray(first[2:])
        seq = 1
        for _, frame in frames[1:]:
            if len(data) >= total or not 2 <= len(frame) <= 8 or frame[0] != (0x20 | seq):
                return None
            needed = min(7, total - len(data))
            if len(frame) - 1 < needed:
                return None
            data.extend(frame[1:1 + needed])
            seq = (seq + 1) & 15
        return bytes(data) if len(data) == total else None

    # -- resilience: reconnect + keepalive -------------------------------- #

    def reconnect(self, attempts=3, reopen=True):
        """
        Reopen the port and restore the live context: ELM init, last header
        (ATSH) and receive filter (ATCRA), and the diagnostic session. Caller
        holds the lock (RLock allows the nested _raw_* calls).
        """
        for i in range(1, attempts + 1):
            try:
                if reopen:
                    self._open()
                cmds = ["ATZ", "ATE0", "ATL0", "ATS1", "ATH1",
                        f"ATSP{self._proto}", "ATCAF1", "ATAT1"]
                if self._proto in ("7", "9"):
                    cmds.append("ATCP 18")
                for cmd in cmds:
                    self._raw_at(cmd, timeout=4 if cmd == "ATZ" else 2)
                    if cmd == "ATZ":
                        time.sleep(0.4)
                if self._sh:
                    self._raw_at(f"ATSH {self._sh}")
                if self._cra:
                    self._raw_at(f"ATCRA {self._cra}")
                if self._session_sub:
                    # restore the session; _raw_write re-checks it against
                    # the read-only guard (default session only)
                    self._raw_write(f"10{self._session_sub}")
                    self._clean(self._read_until_prompt(4))
                self.log.event("PORT", f"reconnected on attempt {i} "
                                       f"(sh={self._sh} cra={self._cra} "
                                       f"session={self._session_sub})")
                return True
            except (OSError, serial.SerialException) as e:
                self.log.event("PORT", f"reconnect attempt {i} failed: {e}")
                time.sleep(1.0)
        self.log.event("PORT", "reconnect FAILED")
        return False

    def start_keepalive(self, interval=None):
        """Start a background tester-present (3E 00) loop to hold the session
        and the Bluetooth link open during idle / human prompts."""
        if not self.ka_enabled:
            return
        if self._ka_thread and self._ka_thread.is_alive():
            return
        if interval is not None:
            self._ka_interval = interval
        self._ka_stop.clear()
        self._ka_thread = threading.Thread(target=self._ka_loop, daemon=True)
        self._ka_thread.start()
        self.log.event("KA", f"keepalive started ({self._ka_interval}s)")

    def stop_keepalive(self):
        if self._ka_thread:
            self._ka_stop.set()
            self._ka_thread.join(timeout=3)
            self.log.event("KA", "keepalive stopped")
        self._ka_thread = None

    def _ka_loop(self):
        while not self._ka_stop.wait(self._ka_interval):
            try:
                if self._session_sub or self._hold_session:
                    # session open: tester-present holds it on the ECU side
                    self.obd("3E00", timeout=2)
                else:
                    # no session yet: adapter-only voltage read keeps the
                    # Bluetooth link alive without putting anything on the bus
                    self.at("ATRV", timeout=2)
            except SafetyError:
                # should never happen (3E00/ATRV are allowed); stop defensively
                self.log.event("KA", "keepalive blocked by guard; stopping")
                break
            except Exception as e:
                self.log.event("KA", f"keepalive error: {e}")

    def set_addressing(self, proto, req, resp):
        """Select protocol + request header + response filter in one place.
          11-bit (proto 6): req '7E0',    resp '7E8'
          29-bit (proto 7): req 'DAD6F1', resp '18DAF1D6' (priority 18 via ATCP)
        resp=None, or an adapter that rejects ATCRA ('?'), falls back to ATAR
        (automatic receive filter derived from the header)."""
        with self._lock:
            if self._proto != proto:
                self.at(f"ATSP{proto}")
            if proto in ("7", "9"):
                self.at("ATCP 18")
            self.at(f"ATSH {req}")
            if resp:
                r = self.at(f"ATCRA {resp}")
                if any("?" in ln for ln in r):
                    self.log.event("INFO", f"adapter rejected ATCRA {resp}; using ATAR")
                    self.at("ATAR")
            else:
                self.at("ATAR")

    def close(self):
        self.stop_keepalive()
        try:
            if self.ser is not None:
                self.ser.close()
        except Exception:
            pass
        self.log.event("PORT", "serial port closed")


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #

# Answers preset from the command line for the READ-ONLY Phase 1 only,
# so Phase 1 does not repeat the startup prompts.
PHASE1_PRESET = {"ignition": None, "engine_running": None}


def confirm(prompt):
    return input(prompt + " [y/N] ").strip().lower() in ("y", "yes")


def ascii_of(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def list_serial_ports():
    """Return a list of pyserial ListPortInfo objects (may be empty)."""
    try:
        from serial.tools import list_ports
    except ImportError:
        return []
    return list(list_ports.comports())


def _looks_like_adapter(p):
    """Heuristic: does this port look like a Bluetooth SPP / ELM adapter?"""
    text = " ".join(
        s for s in (getattr(p, "description", ""), getattr(p, "name", ""),
                    getattr(p, "hwid", "")) if s
    ).lower()
    keys = ("bluetooth", "serial over bluetooth", "spp", "elm", "obd",
            "standard serial", "rfcomm")
    return any(k in text for k in keys)


def print_serial_ports():
    """List available serial ports without opening or probing any device."""
    ports = list_serial_ports()
    if not ports:
        print("No serial ports found.")
        return 0
    print("Detected serial ports (read-only listing; no port was opened):")
    for p in ports:
        tag = "  [Bluetooth/ELM candidate]" if _looks_like_adapter(p) else ""
        desc = getattr(p, "description", "") or ""
        print(f"  {p.device:<16} {desc}{tag}")
    print("\nPass your outgoing Bluetooth serial port explicitly with --port (e.g. --port COM4).")
    return 0


def save_report(path, report, log):
    """Persist the Phase-1 discovery report as JSON for review.
    The report holds the VIN and ECU serial: keep it local; it is git-ignored
    in the project root."""
    doc = {
        "report_version": REPORT_VERSION,
        "saved_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "report": report,
    }
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    log.event("SAVE", f"phase-1 report written: {path}")


# --------------------------------------------------------------------------- #
#  Phase 0 - adapter bring-up and trust test
# --------------------------------------------------------------------------- #

def elm_init(elm, log):
    """Minimal ELM327 configuration (no trust test)."""
    for cmd in ("ATZ", "ATE0", "ATL0", "ATS1", "ATH1", "ATSP6", "ATCAF1", "ATAT1"):
        time.sleep(0.1)
        elm.at(cmd, timeout=6 if cmd == "ATZ" else 3)
        if cmd == "ATZ":
            time.sleep(0.5)


def phase0(elm, log):
    log.event("PHASE", "0 - adapter bring-up & trust test")
    elm_init(elm, log)
    ident = elm.at("ATI")
    volts = elm.at("ATRV")
    log.event("INFO", f"adapter id : {ident}")
    log.event("INFO", f"battery    : {volts}")

    # Trust test: set a header, set a receive filter, request a multi-frame
    # response (VIN 09 02) and confirm >7 bytes reassembled.
    # Try 29-bit functional first (this bike), then 11-bit physical.
    ok = False
    for proto, req in (("7", "DB33F1"), ("6", "7E0")):
        log.event("TEST", f"trust test: protocol {proto} header {req} / multi-frame VIN")
        elm.set_addressing(proto, req, None)
        r = elm.obd("0902", timeout=6)
        payload = r.get("bytes") or b""
        ok = (r.get("ok") and len(payload) == 20 and
              payload[:3] == b"\x49\x02\x01" and
              all(48 <= c <= 57 or 65 <= c <= 90 for c in payload[3:]))
        if ok:
            break
    if ok:
        log.event("PASS", f"reassembled {len(r['bytes'])} bytes: "
                          f"{ascii_of(r['bytes'])!r}")
    else:
        log.event("FAIL", "adapter could not prove multi-frame ISO-TP reassembly")
        print("\n*** This adapter failed the trust test. Many ELM327 clones do. ***")
        print("    Recommend a genuine ELM327 v1.5 or an OBDLink (SX/MX+/LX).")
        print("    Not proceeding on a flaky adapter.\n")
        return False
    elm.at("ATAR")  # reset receive filter
    return True


# --------------------------------------------------------------------------- #
#  Phase 1 - read-only discovery
# --------------------------------------------------------------------------- #

# DiagnosticSessionControl subfunctions used to confirm the DEFAULT session.
# 81 (suppressPosRsp set; ECU 0xD5 answers NRC 0x12) then 01.
# Non-default sessions are refused by the read-only guard.
SESSION_SUBFUNCS = ("81", "01")


# Standard ISO 14229-1 identification DIDs, plus manufacturer-specific ECM
# identity (F1A7) and calibration (F1A0) DIDs, read with ReadDataByIdentifier
# (22 xx xx). Reads only. F190, F18C, F1A7 and F1A0 were confirmed on ECU 0xD5;
# the rest are recorded neutrally as answered / NRC / no reply.
IDENT_DIDS = (
    ("F190", "VIN"),
    ("F18C", "ECU serial number"),
    ("F187", "manufacturer spare part number"),
    ("F188", "manufacturer ECU software number"),
    ("F189", "manufacturer ECU software version"),
    ("F191", "manufacturer ECU hardware number"),
    ("F18A", "system supplier identifier"),
    ("F192", "supplier ECU hardware number"),
    ("F193", "supplier ECU hardware version"),
    ("F194", "supplier ECU software number"),
    ("F195", "supplier ECU software version"),
    ("F197", "system name / engine type"),
    ("F186", "active diagnostic session"),
    ("F1A7", "manufacturer ECM identity DID"),
    ("F1A0", "manufacturer calibration DID"),
)

# Read-only shift-force sensor adaptation status DID (ReadDataByIdentifier
# 22 03 02). Observed on the owner's 2018 Tiger 1200 XRT transitioning
# 00FF -> 0000 -> 00FF across reset and idle relearning; interpretation in
# tsa_analysis remains conditional on firmware match.
SHIFT_FORCE_STATUS_DID = "0302"

# Additional read-only TSA diagnostic DIDs documented in ECU-REFERENCE.md
# (all ReadDataByIdentifier 22 xx xx, permitted by TxGuard). Recorded raw;
# conditional 30174 interpretation is applied offline in tsa_analysis.py.
TSA_DIAG_DIDS = (
    ("0300", "neutral / gear-position sensor adaptation"),
    ("0301", "aggregate gear adaptation"),
    ("0303", "gear 1 adaptation"),
    ("0304", "gear 2 adaptation"),
    ("0305", "gear 3 adaptation"),
    ("0306", "gear 4 adaptation"),
    ("0307", "gear 5 adaptation"),
    ("0308", "gear 6 adaptation"),
    ("013C", "shift-force sensor signal"),
)


def parse_rdbi(did, r):
    """
    Strictly parse one ReadDataByIdentifier result. A positive answer must be
    0x62 followed by the echoed DID; anything else is reported, not trusted.
    Returns a dict with "status" in {"ok", "nrc", "no reply", "unexpected"}.
    """
    b = r.get("bytes")
    if r.get("negative"):
        if not b or len(b) != 3 or b[:2] != b"\x7f\x22":
            return {"status": "unexpected", "raw": b.hex() if b else None}
        return {"status": "nrc", "nrc": f"0x{r['nrc']:02X}", "nrc_name": r["nrc_name"]}
    if not (r.get("ok") and b):
        return {"status": "no reply", "detail": r.get("status")}
    if len(b) < 3 or b[0] != 0x62 or b[1:3].hex().upper() != did.upper():
        return {"status": "unexpected", "raw": b.hex()}
    val = b[3:]
    return {"status": "ok", "hex": val.hex(), "ascii": ascii_of(val)}


def read_identification(elm, log):
    """Read the identification DIDs from the currently addressed ECU."""
    ident = {}
    for did, name in IDENT_DIDS:
        res = parse_rdbi(did, elm.obd(f"22{did}", timeout=4))
        res["name"] = name
        ident[did] = res
        log.event("INFO", f"22 {did} ({name}) -> {res['status']}")
    return ident


def read_shift_force_status(elm, log):
    """Read the shift-force adaptation-status DID (22 03 02).

    Returns a parse_rdbi dict. Raw value (or exact NRC) is preserved for
    conditional offline interpretation in tsa_analysis.
    """
    res = parse_rdbi(SHIFT_FORCE_STATUS_DID,
                     elm.obd(f"22{SHIFT_FORCE_STATUS_DID}", timeout=4))
    log.event("INFO", f"22 {SHIFT_FORCE_STATUS_DID} (shift-force adaptation status) -> {res['status']}")
    return res


def read_tsa_diagnostics(elm, log):
    """Read additional read-only TSA gear adaptation and sensor DIDs (22 xx xx).

    All requests are standard UDS ReadDataByIdentifier reads already permitted
    by TxGuard. Raw values and NRCs are preserved without assuming firmware
    equivalence.
    """
    diag = {}
    for did, name in TSA_DIAG_DIDS:
        res = parse_rdbi(did, elm.obd(f"22{did}", timeout=4))
        res["name"] = name
        diag[did] = res
        log.event("INFO", f"22 {did} ({name}) -> {res['status']}")
    return diag


# ReadDTCInformation requests that reveal a DTC actively requesting the dash
# warning lamp before it latches as a confirmedDTC (0x08 is the only mask this
# engine ECU accepted for the primary read). Status mask 0xAF =
# warningIndicatorRequested(0x80) | testFailedSinceLastClear(0x20) |
# pending(0x04) | testFailed(0x01); 0x2F drops the warning bit; 0x04 is pending
# alone. All three are read-only and already in the TxGuard allowlist. A warning
# lamp lit immediately at key-on while zero DTCs are *confirmed* is exactly the
# state these surface. Full frames (not a composed "1902"+mask) so the static
# source scan sees each complete, allowlisted literal. Broadest mask first.
WARNING_DTC_FRAMES = ("1902AF", "19022F", "190204")


def read_warning_dtcs(elm, log=None):
    """Read 19 02 by warning/pending status masks (read-only, no side effects).

    The primary phase-1 read falls back to the 0x08 (confirmedDTC) mask, which
    is blind to a fault that is already requesting the dash lamp but has not yet
    latched as confirmed. This tries each warning/pending mask in turn, stopping
    at the first that returns a positive 59 02 response, so such a fault is
    surfaced instead of looking "clean". Every attempt (including NRCs and
    no-reply) is recorded, so an ECU that accepts only 0x08 is explicit rather
    than silently empty. Sends only read-only, already-allowlisted frames.
    """
    attempts = []
    chosen = None
    for frame in WARNING_DTC_FRAMES:
        resp = elm.obd(frame, timeout=4)
        parsed = parse_dtcs(resp.get("bytes"))
        parsed["mask"] = frame[4:]
        if not resp.get("bytes"):
            parsed["detail"] = resp.get("status")
        attempts.append(parsed)
        if log is not None:
            log.event("INFO", f"warning-mask DTC read {frame} -> {parsed.get('status')}")
        if parsed.get("status") == "ok":
            chosen = parsed
            break
    result = dict(chosen) if chosen else {"status": "no warning mask accepted"}
    result["attempts"] = attempts
    return result


def read_calibration_discovery(elm, log, req, resp):
    """Read 09 04 from the addressed ECU, before any session request."""
    calibration = elm.obd("0904", timeout=4)
    payload = calibration.get("bytes")
    status = "no reply"
    if payload:
        if len(payload) == 19 and payload[:3] == b"\x49\x04\x01":
            status = "single calibration record"
        elif len(payload) == 3 and payload[:2] == b"\x7f\x09":
            status = "negative response"
        else:
            status = "uninterpreted reply"
    log.event("INFO", f"09 04 calibration discovery -> {status}; access not determined")
    return {
        "request": "0904", "req_id": req, "resp_id": resp,
        "before_session_request": True, "status": status,
        "payload_hex": payload.hex() if payload else None,
        "raw": calibration.get("raw", []), "detail": calibration.get("status"),
    }


def phase1(elm, log, focused=True):
    log.event("PHASE", "1 - read-only UDS discovery")
    report = {}

    print("\nPhase 1 is READ-ONLY (nothing is written to the ECU).")
    print("It may run with the engine idling, so the bike does not time out.")
    print("If the engine is running: bike on its stand, gearbox in NEUTRAL,")
    print("no throttle, foot OFF the gear pedal.")
    preset = PHASE1_PRESET["ignition"] is not None
    if preset:
        ign = PHASE1_PRESET["ignition"]
        engine_running = bool(PHASE1_PRESET["engine_running"])
        log.event("INFO", f"bike state preset on command line: ignition="
                          f"{'ON' if ign else 'OFF'} engine="
                          f"{'RUNNING' if engine_running else 'OFF'}")
        if not ign:
            log.event("STOP", "ignition not on")
            return None
    else:
        if not confirm("Ignition ON?"):
            log.event("STOP", "operator did not confirm ignition on")
            return None
        engine_running = confirm("Is the ENGINE RUNNING?")
    report["phase1_engine_running"] = engine_running
    log.event("INFO", f"phase 1 engine state: "
                      f"{'RUNNING' if engine_running else 'OFF'}")

    # 1. diagnostic ECU (confirmed 0xD5, 29-bit physical addressing)
    proto, req, resp = CONFIRMED_DIAG_ECU
    report["protocol"], report["req_id"], report["resp_id"] = proto, req, resp
    log.event("INFO", f"diagnostic ECU addressing: protocol {proto} req {req} resp {resp}")
    elm.set_addressing(proto, req, resp)

    # Capture calibration discovery (09 04) on D5 before session requests.
    # A reply here does not prove whole-image equivalence or routine support.
    report["calibration_discovery"] = read_calibration_discovery(elm, log, req, resp)

    # 2. default diagnostic session (the only one the read-only guard allows)
    session_sub = None
    for sub in SESSION_SUBFUNCS:
        r = elm.obd(f"10{sub}", timeout=4)
        if (r["ok"] and r["bytes"] and len(r["bytes"]) >= 2
                and r["bytes"][0] == 0x50
                and r["bytes"][1] in (int(sub, 16), int(sub, 16) & 0x7F)):
            session_sub = sub
            log.event("INFO", f"default diagnostic session confirmed, subfunction 0x{sub}")
            break
        if r["negative"]:
            log.event("INFO", f"10{sub} -> NRC {r['nrc_name']}")
    report["session_sub"] = session_sub
    if session_sub is None:
        log.event("INFO", "no explicit session confirmation; reading in the "
                          "ECU's default session")

    # keep-alive: holds the session and the Bluetooth link during the reads
    elm.obd("3E00", timeout=2)
    elm.start_keepalive()

    # 3. UDS identification
    report["identification"] = read_identification(elm, log)

    # 4. shift-force adaptation status DID (22 03 02) and additional read-only
    #    TSA gear adaptation / shift-force sensor DIDs (22 0300..0308, 22 013C).
    report["shift_force_status_did"] = read_shift_force_status(elm, log)
    report["tsa_diagnostics"] = read_tsa_diagnostics(elm, log)

    # Engine D5 does not answer legislated OBD. Read its UDS fault records.
    # This ECU rejects the 0xFF status mask with NRC 0x31 (requestOutOfRange);
    # fall back to the 0x08 (confirmedDTC) mask, which it accepts and which is
    # already in the read-only guard allowlist. Both requests are reads.
    dtcs = elm.obd("1902FF", timeout=4)
    if dtcs.get("negative"):
        ff_nrc = dtcs.get("nrc")
        fb = elm.obd("190208", timeout=4)
        report["uds_dtcs"] = parse_dtcs(fb.get("bytes"))
        report["uds_dtcs"]["mask"] = "08"
        report["uds_dtcs"]["ff_mask_nrc"] = (
            f"0x{ff_nrc:02X}" if ff_nrc is not None else None)
        if not fb.get("bytes"):
            report["uds_dtcs"]["detail"] = fb.get("status")
        # The 0x08 fallback reads confirmedDTCs only. Read the warning/pending
        # masks too so a lamp-requesting fault is not mistaken for a clean ECU.
        report["uds_dtcs_warning"] = read_warning_dtcs(elm, log)
    else:
        report["uds_dtcs"] = parse_dtcs(dtcs.get("bytes"))
        if not dtcs.get("bytes"):
            report["uds_dtcs"]["detail"] = dtcs.get("status")

    # Preserve the historical OBD result for existing report consumers.
    r = elm.obd("03", timeout=4)
    report["dtc_raw"] = r["bytes"].hex() if r["bytes"] else None
    log.event("INFO", f"DTC read (03) -> {report['dtc_raw'] or r.get('status')}")

    report["adaption_reset"] = f"unavailable: {RESET_UNAVAILABLE}"
    report["assessment"] = assess_report(report)

    print("\n" + summary(report))
    log.event("PHASE", "1 complete")
    return report


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Triumph Tiger 1200 XRT TSA diagnostics and guided level-1 shift-force adaptation reset"
    )
    modes = ap.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true", help="stationary read-only bike check")
    modes.add_argument("--l1-reset-now", action="store_true", help="guided one-attempt shift-force adaptation reset (changes ECU state)")
    modes.add_argument("--list-ports", action="store_true", help="list detected serial ports without opening them")
    modes.add_argument("--demo", action="store_true", help="offline synthetic report")
    modes.add_argument("--analyze", metavar="REPORT.json", help="offline saved-report interpretation")
    modes.add_argument("--analyze-bundle", metavar="DIR", help="offline saved reset-bundle summary")
    ap.add_argument("--port", help="explicit outgoing Bluetooth serial port, e.g. COM4")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--report", default="tsa_report.json")
    ap.add_argument("--log", default=None)
    ap.add_argument("--no-keepalive", action="store_true")
    args = ap.parse_args(argv)
    if args.list_ports:
        if args.port:
            ap.error("--list-ports does not take --port")
        if serial is None:
            print("Install pyserial: python -m pip install -r requirements.txt")
            return 2
        return print_serial_ports()
    if args.demo or args.analyze or args.analyze_bundle:
        if args.port:
            ap.error("offline modes do not open serial ports")
        try:
            print("OFFLINE - synthetic or saved observations, not current bike state.")
            if args.analyze_bundle:
                import tsa_session
                print(tsa_session.analyze_bundle(args.analyze_bundle))
            else:
                print(summary(demo_report() if args.demo else read_report(args.analyze)))
            return 0
        except (OSError, ValueError) as e:
            print(f"Cannot analyze: {e}", file=sys.stderr)
            return 2
    if not args.port:
        ap.error("live modes require an explicit --port")
    if serial is None:
        print("Install pyserial: python -m pip install -r requirements.txt")
        return 2
    print("GUIDED RESET (changes ECU state)." if args.l1_reset_now else "READ-ONLY.")
    print("Bike stationary in neutral, ignition ON, stop switch RUN.")
    print("Do not connect while riding. If idling, ensure adequate ventilation.")
    try:
        if not confirm("Ready to connect to the bike in this state?"):
            return 2
        running = confirm("Is the engine idling?")
    except (EOFError, KeyboardInterrupt):
        return 2
    if args.l1_reset_now and running:
        print("Stop the engine before starting the reset workflow.")
        return 2
    PHASE1_PRESET.update(ignition=True, engine_running=running)
    log = None
    elm = None
    bundle = None
    try:
        if args.l1_reset_now:
            import tsa_session
            root = Path(f"tsa_l1now_{datetime.datetime.now():%Y%m%d_%H%M%S_%f}")
            bundle = tsa_session.CaptureBundle(root, {"port": args.port, "synthetic": False, "mode": "l1-reset-now"})
        log = SessionLog(str(bundle.root / "raw.log") if bundle else args.log or f"tsa_session_{datetime.datetime.now():%Y%m%d_%H%M%S}.log", quiet=True)
        elm = Elm327(args.port, args.baud, log, TxGuard(log))
        elm.ka_enabled = not args.no_keepalive
        if bundle:
            journal = tsa_session.AttemptJournal("tsa_l1_now_attempts.jsonl")
            session = tsa_session.Session(elm, log, bundle, journal, sys.modules[__name__])
            return tsa_session.run_l1_reset_now(session)
        if not phase0(elm, log):
            return 1
        elm.start_keepalive()
        report = phase1(elm, log, focused=True)
        if not report:
            return 1
        save_report(args.report, report, log)
        print(f"Report saved to {args.report}. Contains private vehicle identifiers; keep local.")
        return 0 if any(x.get("status") == "ok" for x in report["identification"].values()) else 1
    except (SafetyError, OSError, serial.SerialException) as e:
        print(f"Diagnostic check stopped: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 1
    finally:
        if bundle and bundle.manifest["status"] == "running":
            bundle.update(status="aborted")
        if elm:
            elm.close()
        if log:
            log.close()

if __name__ == "__main__":
    sys.exit(main())
