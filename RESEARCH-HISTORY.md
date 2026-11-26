# Research history

- Early November 2026: physical shift-force sensor wiring repaired; TSA warning remained. Initial read-only tool and guarded transport implemented. Static research examined ECU adaptation state and routine behaviour.
- November 21–24: fault clearance and diagnostic sessions tested on the owner's motorcycle. Fault clearance alone was insufficient. Licensed TuneECU and an OBDLink LX were used to capture legitimate Bluetooth diagnostic communication on the owner's devices.
- November 24–25: initial reset refusal led to a hypothesis about higher security levels. Firmware and client research explored that hypothesis. This was not the final repair route.
- November 26: the ECU accepted the adaptation routine at SecurityAccess level 1. Relearning and persistence were recorded. The owner reported the remaining warning disappeared after riding through the gears and quickshifter operation returned.

The key lesson: distinguish confirmed faults, adaptation state, instrument warning and actual functionality. Negative diagnostic responses must be interpreted in the context of timing and session state. Keep superseded hypotheses clearly marked rather than presenting them as facts.

See [access provenance](ACCESS-PROVENANCE.md) for the independently observed basis of the access mechanism required for this repair.
