# v1.2.0

Supports the camera-ready revision of the SysCom 2026 paper "Downlink Starvation in Shared LoRaWAN Cells".

## Added
- `integration/`: a software-only harness that drives an unmodified ChirpStack v4.19.2 over the Semtech UDP
  interface with authenticated ABP frames, and runs the per-tenant budget at the server's downlink egress.
  Measured result archived in `integration/results_measured.json`: one compliant SF7 device drew 530
  acknowledgments from the server with no per-device limit, and the budget capped it to 3 while the 10 honest
  devices kept their replies.
- Analysis added to `numbers.json` (from the existing experiments, no new simulation): effect on legitimate
  traffic (`honest_denied`), detector precision/recall/FPR/latency (`detector_quality`), per-tenant fairness
  (`fairness`), bucket-depth sensitivity (`honest_denied_bucket`) and the budget's runtime cost (`overhead`).
- `paper/notes/REVIEWER_RESPONSE_LETTER.md`: point-by-point response to the four reviewers.

## Notes
- All paper numbers are produced from `results/numbers.json`; the live-server numbers come from
  `integration/results_measured.json` via `numbers.json`.
- The paper cites the Zenodo concept DOI (10.5281/zenodo.23424369), which resolves to this version.
