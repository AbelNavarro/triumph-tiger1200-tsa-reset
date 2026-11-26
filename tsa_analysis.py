"""Offline report interpretation. No serial, network, or diagnostic execution."""
import json
import re
from pathlib import Path

EVIDENCE = "30174:a104a857a473c85f09e2c239f941ca7aaafa619c40fa5011bc97fcb3559084b5"
STATUS_30174 = {"0000": "Not adapted", "00ff": "Adapted", "00aa": "Feature unavailable"}
BLOCKERS = (
    "Match the installed ECU software/revision to the researched firmware.",
    "Use the manufacturer-approved repair procedure and confirm physical prerequisites.",
    "Verify the repair on this specific motorcycle; one owner's result is not a guarantee.",
)


def value_hex(result):
    if not isinstance(result, dict) or result.get("status") != "ok":
        return None
    value = result.get("hex")
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value):
        return None
    return value.lower()


def assess_report(report):
    """Never promote a calibration number or a positive DID to reset readiness.

    F1A0's image bytes are placeholders (000000); F1A7 reads missing lower
    ROM. There is currently no defensible automatic installed-image matcher.
    The conditional reference decode is therefore separate from bike status.
    """
    ident = report.get("identification", {})
    ident = ident if isinstance(ident, dict) else {}
    key = value_hex(ident.get("F1A7"))
    calibration = value_hex(ident.get("F1A0"))
    status = report.get("shift_force_status_did", {})
    status = status if isinstance(status, dict) else {}
    raw = value_hex(status)
    return {
        "evidence": EVIDENCE,
        "ecm_key_raw": key,
        "ecm_key_matches_profile": key == "201701",
        "calibration_raw": calibration,
        "installed_firmware_match": "unverified",
        "status_raw": raw,
        "status_read": status.get("status", "missing"),
        "status_nrc": status.get("nrc"),
        "bike_adaptation_state": "Unknown (firmware not matched)",
        "reference_30174_meaning": STATUS_30174.get(raw, "Unknown"),
        "reset_available": False,
        "remaining": list(BLOCKERS),
    }


EXPECTED_CALIBRATION_ID = "0030174ECM"
EXPECTED_ECM_KEY = "201701"
FIRMWARE_LIMIT = ("Identifiers only: not a whole-image hash, and the revision "
                  "of the installed software stays unproven.")


def calibration_id(report):
    """ASCII calibration ID from a complete 49 04 01 record, or None."""
    cal = report.get("calibration_discovery")
    value = cal.get("payload_hex") if isinstance(cal, dict) else None
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value):
        return None
    payload = bytes.fromhex(value)
    if len(payload) != 19 or payload[:3] != b"\x49\x04\x01":
        return None
    text = payload[3:].rstrip(b"\x00 \xff")
    if not text or any(not 32 <= c < 127 for c in text):
        return None
    return text.decode("ascii")


def assess_firmware(report):
    """Compare live identifiers with researched image 30174.

    matched: calibration ID and ECM key both equal the researched image.
    different: an identifier positively names something else.
    inconclusive: too little was readable, or the format is not recognized.
    """
    ident = report.get("identification", {})
    ident = ident if isinstance(ident, dict) else {}
    cal_id = calibration_id(report)
    key = value_hex(ident.get("F1A7"))
    reasons = [f"Calibration ID (09 04): {cal_id or 'not readable'}",
               f"ECM key (F1A7): {key or 'not readable'}"]
    number = re.fullmatch(r"0*(\d{5})ECM", cal_id or "")
    if (key is not None and len(key) == 6 and key != EXPECTED_ECM_KEY) or (
            number and number.group(1) != "30174"):
        verdict = "different"
        reasons.append("An identifier differs from researched image 30174; recovery is blocked.")
    elif cal_id == EXPECTED_CALIBRATION_ID and key == EXPECTED_ECM_KEY:
        verdict = "matched"
        reasons.append("Calibration ID and ECM key equal researched image 30174.")
    else:
        verdict = "inconclusive"
        reasons.append("The available identifiers cannot confirm or rule out image 30174.")
    return {"verdict": verdict, "calibration_id": cal_id, "ecm_key": key,
            "evidence": EVIDENCE, "reasons": reasons, "limit": FIRMWARE_LIMIT}


def read_report(path):
    """Accept versioned reports only; do not trust a saved readiness result."""
    doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(doc, dict) or type(doc.get("report_version")) is not int:
        raise ValueError("Expected a versioned TSA report, not a raw log or arbitrary JSON.")
    if doc["report_version"] not in (3, 4) or not isinstance(doc.get("report"), dict):
        raise ValueError("Supported TSA report versions are 3 and 4.")
    return doc["report"]


def summarize_tsa_diagnostics(diag):
    """Conditional offline summary of optional read-only TSA DIDs (ECU-REFERENCE.md)."""
    if not isinstance(diag, dict) or not diag:
        return []
    lines = ["Additional TSA diagnostics (conditional on researched image 30174):"]
    adapt_dids = (
        ("0300", "Neutral / gear-position sensor adaptation"),
        ("0301", "Aggregate gear adaptation"),
        ("0303", "Gear 1 adaptation"),
        ("0304", "Gear 2 adaptation"),
        ("0305", "Gear 3 adaptation"),
        ("0306", "Gear 4 adaptation"),
        ("0307", "Gear 5 adaptation"),
        ("0308", "Gear 6 adaptation"),
    )
    for did, label in adapt_dids:
        entry = diag.get(did)
        if not isinstance(entry, dict):
            continue
        raw = value_hex(entry)
        if raw is not None:
            meaning = STATUS_30174.get(raw, "Unknown")
            lines.append(f"  {did} ({label}): raw {raw} -> {meaning}")
        elif entry.get("status") == "nrc":
            lines.append(f"  {did} ({label}): NRC {entry.get('nrc')} {entry.get('nrc_name', '')}".rstrip())
        else:
            lines.append(f"  {did} ({label}): {entry.get('status', 'unavailable')}")
    adc = diag.get("013C")
    if isinstance(adc, dict):
        raw = value_hex(adc)
        if raw is not None and len(raw) == 2:
            val = int(raw, 16)
            if val <= 0x18:
                note = "low fault rail (<=0x18; check sensor/wiring for short to ground or open)"
            elif val >= 0xD9:
                note = "high fault rail (>=0xD9; check sensor/wiring for open or short high)"
            elif 0x7B <= val <= 0x8F:
                note = "within nominal rest window (0x7B..0x8F)"
            else:
                note = "outside rest window (pedal loaded or sensor offset)"
            lines.append(f"  013C (Shift-force sensor signal): raw {raw} ({val}) -> {note}")
        elif raw is not None:
            lines.append(f"  013C (Shift-force sensor signal): raw {raw} (unexpected length)")
        elif adc.get("status") == "nrc":
            lines.append(f"  013C (Shift-force sensor signal): NRC {adc.get('nrc')} {adc.get('nrc_name', '')}".rstrip())
        else:
            lines.append(f"  013C (Shift-force sensor signal): {adc.get('status', 'unavailable')}")
    return lines if len(lines) > 1 else []


def summary(report, guided=False):
    """guided: the bike-session flow reports recovery outcomes separately."""
    a = assess_report(report)
    lines = ["TSA CHECK RESULT"]
    if not guided:
        lines.append("Reset: not performed in read-only mode (use --l1-reset-now for guided repair).")
    lines += ["Bike adaptation state: " + a["bike_adaptation_state"],
             "ECM key (F1A7): " + (a["ecm_key_raw"] or "not read"),
             "Calibration bytes (F1A0): " + (a["calibration_raw"] or "not read")]
    if a["ecm_key_matches_profile"]:
        lines.append("ECM key matches the research profile; this does not identify the firmware.")
    discovery = report.get("calibration_discovery")
    if isinstance(discovery, dict):
        lines.append("D5 calibration discovery: " + str(discovery.get("status", "unknown")) +
                     " (access not determined)")
    if a["status_raw"] is not None:
        lines.append("Sensor status bytes: " + a["status_raw"])
        lines.append("If firmware matches researched 30174: " + a["reference_30174_meaning"])
    else:
        lines.append("Sensor status read: " + str(a["status_read"]) +
                     (" (NRC " + str(a["status_nrc"]) + ")" if a["status_nrc"] else ""))
    lines += summarize_tsa_diagnostics(report.get("tsa_diagnostics"))
    dtc = report.get("uds_dtcs", {})
    if isinstance(dtc, dict) and dtc.get("status") == "ok":
        records = dtc.get("records", [])
        if not isinstance(records, list):
            records = []
        lines.append(f"Engine ECU fault records: {len(records)}")
        for record in records:
            if not isinstance(record, dict):
                continue
            active = record.get("test_failed")
            state = ("latest test marked failed" if active is True else
                     "not marked failed (test may not have run)" if active is False else
                     "test-failure status unavailable")
            lines.append(f"  {record.get('dtc_hex')} / status {record.get('status_hex')}: {state}")
            raw = record.get("dtc_hex")
            if isinstance(raw, str) and re.fullmatch(r"[0-9a-fA-F]{6}", raw):
                first = int(raw[:2], 16)
                code = "PCBU"[first >> 6] + str((first >> 4) & 3) + raw[1:4].upper()
                lines.append(f"    If SAE format (unverified): {code}-{raw[4:].upper()}")
        lines.append("DTCs shown as raw 3-byte identifiers; no SAE P-code format assumed.")
    else:
        lines.append("Engine ECU fault read: " + str(dtc.get("status", "not collected") if isinstance(dtc, dict) else "unknown"))
    warn = report.get("uds_dtcs_warning")
    if isinstance(warn, dict):
        lines += warning_indicator_lines(warn)
    if not guided:
        lines += ["Still needed before a reset:"] + ["  - " + item for item in a["remaining"]]
    return "\n".join(lines)


def demo_report():
    """Synthetic input, explicitly labelled; never a recorded bike response."""
    return {"synthetic": True, "protocol": "7", "req_id": "DAD5F1",
            "resp_id": "18DAF1D5", "identification": {
                "F1A7": {"status": "ok", "hex": "201701"},
                "F1A0": {"status": "ok", "hex": "000000"}},
            "shift_force_status_did": {"status": "ok", "hex": "0000"},
            "tsa_diagnostics": {
                "0300": {"status": "ok", "hex": "00ff"},
                "0301": {"status": "ok", "hex": "00ff"},
                "013C": {"status": "ok", "hex": "85"},
            },
            "uds_dtcs": {"status": "not collected"}}


def _mask_has_warning_bit(hexval):
    """True only if a status-mask hex string clearly includes bit 7 (0x80)."""
    try:
        return bool(int(hexval, 16) & 0x80)
    except (TypeError, ValueError):
        return False


def _dtc_record_line(record):
    """One summary line for a DTC record, plus its unverified SAE P-code line."""
    out = []
    bits = [name for name, key in (("warning-lamp", "warning_requested"),
                                   ("pending", "pending"),
                                   ("test-failed", "test_failed"),
                                   ("confirmed", "confirmed"))
            if record.get(key) is True]
    out.append(f"  {record.get('dtc_hex')} / status {record.get('status_hex')}"
               + (f" [{', '.join(bits)}]" if bits else ""))
    raw = record.get("dtc_hex")
    if isinstance(raw, str) and re.fullmatch(r"[0-9a-fA-F]{6}", raw):
        first = int(raw[:2], 16)
        code = "PCBU"[first >> 6] + str((first >> 4) & 3) + raw[1:4].upper()
        out.append(f"    If SAE format (unverified): {code}-{raw[4:].upper()}")
    return out


def warning_indicator_lines(warn):
    """Summary lines for a warning/pending-mask DTC read (read_warning_dtcs).

    The warning-indicator question has three honest answers, decided in order:

    1. Request observed  — some returned record has warningIndicatorRequested
       set. Name those DTCs; state the engine ECU reports a warning-indicator
       request. Whether it is the TSA dashboard message is a separate question.
    2. No request observed — ONLY when the read parsed OK, the accepted request
       mask included 0x80, the ECU's status_availability_mask included 0x80, and
       no record had that bit set. Scope it to the engine ECU at read time.
    3. Undetermined — everything else (an empty pending-only 0x04 read, the
       warning bit unavailable, a rejected read, or missing mask fields in an
       older report). It is NOT evidence the lamp is unrequested; still show any
       pending / failed / confirmed DTCs with their individual flags.
    """
    lines = []
    records = warn.get("records") if isinstance(warn.get("records"), list) else []
    records = [r for r in records if isinstance(r, dict)]
    requesting = [r for r in records if r.get("warning_requested") is True]
    mask = warn.get("mask")
    parsed_ok = warn.get("status") == "ok"
    can_answer = (parsed_ok and _mask_has_warning_bit(mask)
                  and _mask_has_warning_bit(warn.get("status_availability_mask")))

    if requesting:  # rule 1
        named = ", ".join(r.get("dtc_hex", "?") for r in requesting)
        lines.append(f"Warning-indicator request: the engine ECU reports "
                     f"warningIndicatorRequested set on {named} (mask {mask or '?'}).")
        lines.append("  Whether this is the TSA dashboard message is a separate question.")
    elif can_answer:  # rule 2
        lines.append("Warning-indicator request: none from the engine ECU at the time "
                     f"of this read (mask {mask}, warning bit supported).")
    else:  # rule 3
        lines.append("Warning-indicator request: undetermined — this read did not report "
                     f"warning-indicator status (warning mask read: {warn.get('status', 'not collected')}"
                     + (f", mask {mask}" if mask else "")
                     + "). This does not prove no DTC requests the lamp.")

    for record in records:
        lines += _dtc_record_line(record)
    return lines


def parse_dtcs(payload):
    """Strict UDS 19/02 decoder; preserve 24-bit DTCs without guessing format."""
    if not payload:
        return {"status": "no reply"}
    raw = payload.hex()
    if len(payload) == 3 and payload[:2] == b"\x7f\x19":
        return {"status": "nrc", "nrc": f"0x{payload[2]:02X}", "raw": raw}
    if len(payload) < 3 or payload[:2] != b"\x59\x02" or (len(payload) - 3) % 4:
        return {"status": "unexpected", "raw": raw}
    available = payload[2]
    records = []
    for pos in range(3, len(payload), 4):
        status = payload[pos + 3]
        records.append({"dtc_hex": payload[pos:pos + 3].hex().upper(),
                        "status_hex": f"{status:02X}",
                        "test_failed": bool(status & 1) if available & 1 else None,
                        "pending": bool(status & 4) if available & 4 else None,
                        "confirmed": bool(status & 8) if available & 8 else None,
                        # warningIndicatorRequested (bit 7): the DTC is actively
                        # asking for the dash warning lamp, which can be set long
                        # before the DTC latches as confirmedDTC (bit 3).
                        "warning_requested": bool(status & 0x80) if available & 0x80 else None})
    return {"status": "ok", "raw": raw, "status_availability_mask": f"{available:02X}",
            "records": records}
