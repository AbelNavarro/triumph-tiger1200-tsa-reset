# Quickstart

The public edition includes read-only checks and a separate guided level-1 shift-force adaptation reset. Only attempt the reset after diagnosis and physical repair, using the confirmed model. Consult a qualified Triumph technician if uncertain.

## Install and rehearse

Python 3.10 is the development baseline. In a terminal at the repository root:

```sh
python -m pip install -r requirements.txt
python tsa_adaption_reset.py --demo
python tests/run_all.py
```

The demo and tests need no adapter or bike.

## Read-only diagnostics

This public derivative has not been separately validated on hardware. Before connecting, have the shift-force sensor and wiring checked and repaired. Confirm the motorcycle's identity; a model name alone does not establish ECU compatibility. If in doubt, consult a qualified Triumph technician.

Pair your adapter and identify the outgoing serial port (e.g. COM4 on Windows). You can list detected serial ports without opening any device:

```sh
python tsa_adaption_reset.py --list-ports
```

With the bike stationary in neutral, ignition on and the stop switch in RUN, run:

```sh
python tsa_adaption_reset.py --check --port COM4
```

Follow the safety prompts. Do not connect while riding. Stop if unexpected behaviour or an adapter trust-test failure occurs. The check saves a report containing private identifiers. Do not post the raw report or log online.

For a saved version 3/4 report, run `python tsa_adaption_reset.py --analyze tsa_report.json` offline. For a saved reset capture bundle, run `python tsa_adaption_reset.py --analyze-bundle <bundle_dir>` offline.

## Repair and relearning

A reset of the gear-position adaptation is not part of the demonstrated necessary repair. Gear learning had been independently disturbed during the owner's research, so do not deliberately repeat that experiment.

A successful DTC clear or an adapted-state reading is not a roadworthiness test. Follow manufacturer guidance for relearning and stop riding if shifting is abnormal.

## Guided shift-force adaptation reset

This changes ECU state. Use only after the underlying hardware fault has been repaired. Confirm this is a 2018 Tiger 1200 XRT, ignition on, engine off, neutral, stable battery supply, in a ventilated area. Run the read-only check first. Review the report and do not proceed if ECU identifiers differ or readings are unexpected.

```sh
python tsa_adaption_reset.py --l1-reset-now --port COM4
```

Follow the consent and safety prompts. The tool saves a baseline, checks ECU identity, performs the single guarded reset attempt, guides relearning at idle and checks the adapted state after an ignition cycle. If a response is uncertain, stop; do not retry or delete the journal. Keep the report, capture directory and journal private. A refused operation is not an invitation to try a different access level.

A successful reset does not clear unrelated faults. Gear learning is distinct; the owner needed to complete it because it had independently been reset during testing. The warning then disappeared. Do not deliberately reset gear learning. Consult the manufacturer procedure before riding, and stop if shifting is abnormal.
