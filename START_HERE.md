# DLGuard: paper and code (project folder)

**To submit: open `SUBMISSION/`.** It has the PDF to upload and `CMT_FORM.md` with the title, abstract, keywords,
authors and AI-use answer ready to paste into Microsoft CMT.

Everything for the SysCom 2026 paper and its code lives in this one folder. It is a git repository; every
deleted or older file can be recovered from its history.

## The paper

- **Submit this file:** `paper/conference/DLGuard_SysCom2026.pdf` (6 pages, SCITEPRESS template, PDF only, via
  Microsoft CMT; choose the "Secure Systems" special session).
- Editable version: `paper/conference/DLGuard_SysCom2026.docx`.
- Rebuild after any change (every number is read from `results/numbers.json`):
  ```
  python3 paper/build_conference.py      # writes the .docx
  python3 paper/check_conference.py      # number and style check -> paper/conference/CHECK_REPORT.md
  soffice --headless --convert-to pdf --outdir paper/conference paper/conference/DLGuard_SysCom2026.docx
  ```
- The code version and DOI cited in the paper are set at the top of `paper/build_conference.py`.

## Notes (`paper/notes/`)

- `MAINTAINER_DISCLOSURE_DRAFTS.md`: notes to send privately to the ChirpStack and The Things Stack maintainers
  before the paper is public (the paper's ethics paragraph promises this).
- `REVIEW_SYSCOM.md`: the referee-style review, with what was fixed and what is open.
- `REFERENCES_TO_VERIFY.md`: how far each reference was checked. `SERVER_SOURCES.md`: the server source lines the
  paper relies on. `VENUE.md`: SysCom and template rules. `AI_DISCLOSURE.md`: the disclosure wording.
  `CHANGELOG.md`: every change to code, experiments and paper, with evidence.

## Archive (`paper/archive/`)

- `DLGuard_IEEE_paper_long_version.docx`: the original long IEEE-format draft (Oct. 15), a starting point for a
  journal version.

## The code

The rest of this folder is the public repository: https://github.com/lohith9/lorawan-downlink-starvation
(`README.md` explains it). Archived on Zenodo: all versions doi:10.5281/zenodo.23424369; the version the paper
cites, v1.1.1, doi:10.5281/zenodo.23426958. `paper/` is not part of the public repository.
