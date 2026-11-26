# ECU reference — reviewed observations

The 2018 XRT investigation used UDS over CAN through a compatible serial OBD adapter. The application preserves raw diagnostic identifiers, negative responses and transport errors rather than silently treating them as successful reads.

| Read-only data identifier | Interpretation in researched image 30174 |
| --- | --- |
| 0300 | Neutral / gear-position sensor adaptation |
| 0301 | Aggregate gear adaptation |
| 0302 | Shift-force sensor adaptation |
| 0303–0308 | Individual gear adaptation |
| 013C | Shift-force sensor input |

For the adaptation indicators, the researched image maps 0000 to not adapted, 00FF to adapted and, where supported, 00AA to unavailable. For `013C`, the researched image maps the 1-byte shift-force sensor signal to a nominal rest window around `0x7B..0x8F` and sensor rail fault thresholds at `<= 0x18` and `>= 0xD9`. These interpretations are conditional; installed firmware equivalence was not established. The tool reads these identifiers in `--check` (strictly read-only `22 xx xx`) and preserves raw values and negative responses without inferring adaptation from an unsupported identifier.

The instrument warning and confirmed DTC records are distinct indicators. A successful adaptation response is not a substitute for functional verification.

## References

- Triumph Technical Bulletin 205: consult a legitimate workshop-information source for the manufacturer procedure.
- AUTOSAR Classic Platform, Diagnostic Communication Manager, R22-11: https://www.autosar.org/fileadmin/standards/R22-11/CP/AUTOSAR_SWS_DiagnosticCommunicationManager.pdf
- ISO 14229 (UDS), ISO 15765 (CAN transport): official standards catalogue, https://www.iso.org/
- Renesas SH-2A software manual: original publisher, https://www.renesas.com/

No third-party manuals, firmware or proprietary source are distributed with this documentation.
