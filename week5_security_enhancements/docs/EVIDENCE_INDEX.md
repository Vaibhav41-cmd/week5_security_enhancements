# Evidence index

This index connects each claim in the README, security audit and Word report
to a reproducible artefact. Unless a row says otherwise, regenerate the set
from the repository root with:

```bash
python tools/generate_evidence.py
```

## Summary artefacts

| Artefact | What it proves | How to inspect |
|---|---|---|
| `results/security_summary.json` | Machine-readable final environment, test totals/markers, Bandit totals/issues, vulnerability register and source LOC | Open as JSON; this is the source used to cross-check report numbers |
| `docs/evidence/verification_summary.txt` | Human-readable one-page verification outcome | Read the text file; expected `58 passed, 0 failed` |
| `docs/evidence/environment.txt` | Python/package versions and principal security parameters used for evidence | Compare with local `python --version` and installed packages |
| `docs/evidence/cli_help.txt` | The hardened CLI starts and exposes the documented command surface | Compare with `python run.py --help` |

## Test and workflow transcripts

| Artefact | Contents | Expected result |
|---|---|---|
| `docs/evidence/pytest_full.txt` | Complete `python -m pytest -vv` output with every collected test name | `58 passed` |
| `docs/evidence/workflow_demo.txt` | Output of `python examples/demo.py`: two users, encrypted notes, search, Bob denied, ciphertext glimpse, owner export and password rotation | Final line decrypts Alice's note under the new password |
| `docs/evidence/attack_demo.md` | 13 vulnerability rows and 2 legitimate-workflow rows against baseline and hardened builds | Baseline exploitable/exposed 13/13; hardened blocked/protected 13/13 |
| `docs/evidence/attack_demo_run.txt` | Raw stdout from executing the attack harness with its `--output` argument | Same table as `attack_demo.md` |

## Static-analysis artefacts

| Artefact | Target | Expected result |
|---|---|---|
| `results/security_scans/bandit_baseline.txt` | `vulnerable/vulnerable_app.py` | 7 issues: 1 Low, 4 Medium, 2 High |
| `results/security_scans/bandit_baseline.json` | Same baseline scan in machine-readable form | B608 ×3, B324 ×1, B403 ×1, B301 ×1, B605 ×1 |
| `results/security_scans/bandit_secure.txt` | `securenotes/` production package | 0 issues |
| `results/security_scans/bandit_secure.json` | Same secure scan in machine-readable form | 0 results; one explained B105 false positive is suppressed only on the algorithm-label constant |

## Figures used in the Word report

| Figure | File | Interpretation |
|---|---|---|
| Figure 1 | `docs/evidence/figures/fig01_threat_model.png` | Actors and trust boundaries: validation, authorization, crypto/session and controlled files |
| Figure 2 | `docs/evidence/figures/fig02_bandit_before_after.png` | Bandit severity and manual-register severity before/after remediation |
| Figure 3 | `docs/evidence/figures/fig03_crypto_session_flow.png` | Separate password-verifier salt, encryption-key salt, memory-only Fernet key and hashed session digest |
| Figure 4 | `docs/evidence/figures/fig04_attack_results_matrix.png` | One-row-per-vulnerability paired attack outcome |
| Figure 5 | `docs/evidence/figures/fig05_workflow_demo.png` | Legitimate service workflow, cross-user denial and password rotation |
| Figure 6 | `docs/evidence/figures/fig06_pytest_results.png` | Excerpt of the complete verbose pytest transcript, ending in `58 passed` |

## Source-to-evidence traceability

| Finding | Primary secure implementation | Baseline proof | Hardened proof |
|---|---|---|---|
| V-01 SQL injection | `securenotes/db.py`, `auth.py`, `service.py` | 2 baseline attack tests; Bandit B608 | SQLi auth/search tests |
| V-02 MD5 | `securenotes/crypto.py` | Exact MD5 test; Bandit B324 | PBKDF2 salt/tamper tests |
| V-03 IDOR | `securenotes/service.py` owner predicates | Unscoped `get_note` test | Bob read/update/delete test |
| V-04 plaintext | `crypto.py`, note ciphertext columns | Raw DB secret test | Raw DB/WAL/SHM absence test |
| V-05 sessions | `crypto.py`, `auth.py` sessions | Current-second/raw DB token test | Digest, expiry, revoke tests |
| V-06 pickle | JSON branch in `service.import_notes` | Marker-file canary; B301/B403 | Extension/schema/size rejection tests |
| V-07 traversal | `validation.safe_join` | Escaped export test | Four filename forms rejected |
| V-08 command injection | SQLite backup API in `service.py` | Marker via semicolon; B605 | Marker absent; valid backup works |
| V-09 enumeration/lockout | `auth.authenticate` | Distinct baseline messages | Generic message + lock/expiry tests |
| V-10 errors/logs | `errors.py`, `audit.py`, CLI handler | Secret log substrings | Audit/CLI secret-absence tests |
| V-11 input limits | `validation.py` and CLI/service bounds | 20,000-char body accepted | Boundary/parameter tests |

## Reproduction checklist

From a fresh clone/extraction at the repository root:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt -r requirements-evidence.txt
python -m pytest -vv
python tools/attack_demo.py --output /tmp/week5-attacks.md
bandit -r vulnerable/vulnerable_app.py
bandit -r securenotes
python examples/demo.py
```

(The `/tmp` attack output in this checklist is only a terminal example path;
use any local writable path. It is not used by application code.)

A successful reproduction should agree on:

- 58 tests collected/passed;
- marker collection 9 attack / 44 security / 6 functionality;
- baseline Bandit total 7 and secure total 0;
- 11 manual vulnerability classes;
- attack matrix 13/13 before exploitable and 13/13 after blocked/protected;
- workflow demo ending with successful decryption after password rotation.

## Evidence handling notes

- Synthetic accounts use documented test passwords; no real credential is in
  the transcripts.
- Session tokens are redacted in human-readable workflow output.
- Absolute workspace paths are replaced with `<project-root>` in generated
  displayed transcripts. This is a display normalization only; commands are
  still reproducible from the repository root.
- Attack markers/databases are created in temporary directories and are not
  packaged.
- Generated caches, live databases, exports and virtual environments are
  excluded from the submission archives.
