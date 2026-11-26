# Triumph Tiger 1200 TSA reset

Independent repair research and diagnostic software for the Triumph Tiger 1200 XRT quickshifter (Triumph Shift Assist, TSA), including persistent warnings after shift-force sensor or wiring repair, P1702/P1703 and Technical Bulletin 205.

**Repair confirmed by the owner on a 2018 Tiger 1200 XRT on November 26, 2026.**

The wiring had been repaired, but clearing the fault codes alone did not restore the quickshifter. The ECU subsequently accepted a dedicated shift-force sensor adaptation reset and retained the learned state across an ignition cycle. A remaining dashboard warning disappeared after the owner rode through the gears, and the quickshifter worked again.

## What this repository contains

This project includes read-only checks, offline evidence interpretation and the guided level-1 shift-force adaptation reset derived from the workflow that restored the owner’s motorcycle. The public edition is an experimental derivative; other motorcycles and exact firmware equivalence remain unverified.

- [Quickstart](QUICKSTART.md)
- [Technical findings](FINDINGS.md)
- [ECU reference](ECU-REFERENCE.md)
- [Research history](RESEARCH-HISTORY.md)
- [Compatibility](COMPATIBILITY.md)
- [Safety](SAFETY.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

The access mechanism required for the demonstrated repair is included; see [access provenance](ACCESS-PROVENANCE.md). One motorcycle was validated; other models and firmware are not confirmed.

Author: Abel Navarro. Original material is MIT-licensed. Independent project, not affiliated with Triumph, Keihin, TuneECU or OBDLink. All trademarks belong to their owners.

## Usage

```sh
python -m pip install -r requirements.txt
python tsa_adaption_reset.py --demo
python tsa_adaption_reset.py --list-ports
python tsa_adaption_reset.py --check --port COM4
# Only after physical repair and the safety checks in QUICKSTART.md:
python tsa_adaption_reset.py --l1-reset-now --port COM4
# Offline inspection of a saved report or reset bundle:
python tsa_adaption_reset.py --analyze tsa_report.json
python tsa_adaption_reset.py --analyze-bundle tsa_l1now_YYYYMMDD_HHMMSS_ffffff
```

The reset changes ECU adaptation state and requires explicit owner consent. No gear adaptation reset, DTC clear, programming-mode or firmware-writing operation is included. Keep all local captures private. See [SAFETY.md](SAFETY.md).
