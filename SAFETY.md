# Safety and limitations

Experimental repair research for restoring original function after the underlying fault is repaired. It is not a substitute for a workshop manual or qualified technician. The original owner-run workflow succeeded on one 2018 Triumph Tiger 1200 XRT; the public derivative has not independently been tested on hardware.

- Start with read-only checks and preserve the original evidence.
- Work stationary in neutral with stable battery supply, ignition on and engine off for the reset; ensure adequate ventilation for idle relearning. Do not connect while riding.
- Do not continue if hardware remains faulty, compatibility is uncertain or the ECU identity differs. Inconclusive firmware identifiers require explicit acknowledgement; this is not evidence of compatibility.
- The guided reset sends only the limited access and shift-force routine frames. A persistent local journal reserves attempts before sending, so the tool does not repeat an uncertain reset. Do not delete the journal to retry.
- A failed or unexpected response is a stop condition. Consult a qualified technician. No higher-level access, programming, firmware writing, arbitrary fault clearing, immobilizer or emissions operations are provided.
- A cleared DTC or adapted-state reading does not establish roadworthiness. Follow manufacturer guidance for relearning; stop riding if shifting is abnormal.
- Raw reports, captures and journals contain vehicle identifiers and diagnostic exchanges. Keep them private.

No warranty or support commitment is implied by publication.
