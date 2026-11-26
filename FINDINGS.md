# Verified findings

| Finding | Evidence level |
| --- | --- |
| Clearing stored faults alone did not restore the quickshifter | Owner observation, November 24 |
| The ECU accepted the shift-force adaptation reset at SecurityAccess level 1 | Live ECU response, November 26 |
| An intervening delay was associated with an earlier refusal; the later run without intervening operations succeeded | Live comparison; timeout is the leading explanation, not a measured universal limit |
| Adaptation state changed and persisted across ignition cycling | Live ECU readback, November 26 |
| A remaining warning can be associated with incomplete gear adaptation | Static firmware analysis and subsequent owner road-test report; exact pre/post gear-state readback not established here |
| Warning disappeared and quickshifter worked after a short ride through the gears | Owner-reported functional test, November 26 |

The earlier hypothesis that higher security levels were necessary for this repair is superseded. No programming-mode access or reflash was needed in the successful session.

## Scope of verification

The logged successful session records ECU acceptance, relearning, ignition-cycle persistence and no returning confirmed faults on the supported read. The road test is a separate first-person observation, not an instrumented capture. Exact whole-image equivalence between the researched 30174 image and installed ECU remains unproven.

The private evidence archive retains dated captures and analyses; this public-facing summary intentionally does not distribute proprietary code, raw captures, unrelated access mechanisms, or executable disassembly.

The access mechanism used for the successful shift-force reset was independently determined from observed Bluetooth traffic. See [access provenance](ACCESS-PROVENANCE.md). The full permission scope of level 1 is not established.
