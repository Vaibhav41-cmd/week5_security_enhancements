# Week 5 — Security Enhancements in Python Applications

## SecureNotes: from an exploitable notes CLI to a hardened application

SecureNotes is a local, multi-account notes command-line application built as a
security-engineering case study. The project deliberately preserves a small,
quarantined **vulnerable baseline**, proves how it can be exploited, and then
implements the same user workflows in a hardened package.

The point is not merely that the final code “uses hashing and encryption.” Each
finding is connected to:

1. the unsafe baseline behaviour;
2. a concrete local attack and its impact;
3. the replacement control and why it was chosen;
4. an automated regression test and/or before/after attack transcript.

> **Safety warning:** `vulnerable/vulnerable_app.py` is intentionally unsafe.
> It exists only for local audit demonstrations with synthetic data. Never
> deploy it, expose it on a network, or use real credentials/notes with it.
> The submitted application is the `securenotes/` package, started with
> `python run.py`.

## Headline results

| Measure | Vulnerable baseline | Hardened SecureNotes |
|---|---:|---:|
| Manual vulnerability classes audited | 11 | 11 fixed and regression-tested |
| Baseline severity profile | 3 Critical, 5 High, 3 Medium | 0 known in-scope residual findings |
| Bandit findings in the compared target | 7 (1 Low, 4 Medium, 2 High) | 0 unsuppressed findings |
| Attack-demo vulnerability rows | 13 exploitable/exposed | 13 blocked/protected |
| Legitimate-workflow checks in attack demo | Works insecurely | 2/2 still work securely |
| Automated tests | — | **58 passed** |
| Password storage | Unsalted MD5 | PBKDF2-HMAC-SHA256, per-user salt, 600,000 iterations |
| Notes at rest | Plaintext SQLite columns | Fernet ciphertext for title, body and tags |
| Sessions | Predictable, raw, non-expiring | 256-bit random bearer token; only SHA-256 digest stored; 30-minute expiry |
| Import | Unsafe `pickle` | Bounded, schema-validated JSON only |
| Backup | Shell string (`os.system`) | SQLite backup API, atomic safe-file creation, no shell |

Test breakdown: 9 quarantined baseline attack demonstrations, 44
security-marker tests and 6 functionality-marker tests (markers can overlap;
58 tests are collected in total).

![Before/after attack outcomes](docs/evidence/figures/fig04_attack_results_matrix.png)

## What the application does

A user can:

- register and authenticate with a hidden password prompt;
- create, list, read, update, delete and literally search encrypted notes;
- validate and revoke a session token;
- export only their own notes as JSON;
- import a bounded JSON notes file;
- create a SQLite backup without invoking a shell;
- change password, which re-encrypts all notes under a new key and revokes
  older sessions.

The database is local SQLite. There is no network server in this project. The
threat model therefore concentrates on malicious local input, another
application account, unsafe files, and disclosure of the database/backup.

## Quick start — run from this repository root

All commands below assume the terminal is already in the directory containing
this `README.md`. Do **not** add another `cd week5_security_enhancements`:
the GitHub-ready archive is designed so its contents sit at the repository
root.

### 1. Create an environment and install dependencies

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Python 3.10 or newer is required. `cryptography` is the only runtime
third-party dependency.

### 2. Register and add a note

Passwords are entered through hidden prompts. They must be 12–128 characters
and use at least three of: lowercase, uppercase, digit and symbol.

```bash
python run.py register --username alice
python run.py add --username alice --title "Project plan" --body "Call the supplier on Tuesday" --tags work,planning
python run.py list --username alice
python run.py get --username alice --id 1
python run.py search --username alice --query supplier
```

For genuinely sensitive text, prefer `--body-file` over `--body`, because a
command-line body may be retained in shell history:

```bash
python run.py add --username alice --title "Private note" --body-file private-note.txt
```

### 3. Session commands

`register` and `login` print a bearer token once. Treat it like a password.
For `whoami` and `logout`, omit `--token` interactively so the token is read
through a hidden prompt instead of appearing in shell history:

```bash
python run.py whoami
python run.py logout
```

Most note commands still ask for the account password because the session
token proves identity but cannot derive the note-decryption key. That is a
deliberate separation: stealing the session table does not reveal either a
usable token or note plaintext.

### 4. Import, export, update, delete, backup and password rotation

```bash
python run.py import --username alice data/sample_import.json
python run.py export --username alice alice-notes.json
python run.py update --username alice --id 1 --title "Updated plan"
python run.py delete --username alice --id 1
python run.py backup --username alice secure-backup.db
python run.py change-password --username alice
```

> Exports intentionally contain decrypted notes so the owner can move them.
> SecureNotes writes them owner-only where POSIX permissions are supported,
> but the user must still protect/delete export files appropriately.

## Verify the security work

Install development/evidence tools:

```bash
python -m pip install -r requirements-dev.txt -r requirements-evidence.txt
```

Run the complete test suite:

```bash
python -m pytest -vv
```

Expected final line:

```text
58 passed
```

Run only particular evidence groups:

```bash
python -m pytest -m attack -q       # baseline attacks intentionally succeed
python -m pytest -m security -q     # hardened controls
python -m pytest -m functionality -q
```

Run the same attacks against both implementations:

```bash
python tools/attack_demo.py
```

Run Bandit on the before/after targets:

```bash
bandit -r vulnerable/vulnerable_app.py
bandit -r securenotes
```

Expected interpretation: the quarantined file reports 7 findings; the secure
package reports none. Bandit flagged the public algorithm label
`"pbkdf2_sha256"` as a possible hard-coded password during triage. It is not a
credential, so only that constant has a targeted, explained `# nosec B105`.

Run the legitimate workflow demo and regenerate all evidence:

```bash
python examples/demo.py
python tools/generate_evidence.py
```

## Vulnerability summary

| ID | Baseline weakness | Hardened control |
|---|---|---|
| V-01 | SQL string interpolation in login/search | Bound parameters everywhere; encrypted owner-scoped literal search |
| V-02 | Fast, unsalted MD5 password storage | PBKDF2-HMAC-SHA256, random salt, 600,000 iterations, constant-time compare |
| V-03 | Note lookup by ID without owner check (IDOR) | `WHERE id = ? AND user_id = ?` on read/update/delete; foreign and missing IDs both return “Note not found” |
| V-04 | Plaintext title/body/tags in SQLite | Password-derived Fernet encryption with a separate key salt |
| V-05 | Predictable raw non-expiring session token | `secrets` token, SHA-256 digest at rest, expiry, revocation |
| V-06 | `pickle.load` on an import file | JSON only, extension/size/count/schema/type validation |
| V-07 | Caller-controlled export path | Strict basename allow-list plus resolved-parent check |
| V-08 | User text embedded in an `os.system` backup command | SQLite backup API; validated basename; no shell |
| V-09 | Account-enumeration messages and unlimited guesses | Identical public login failure, dummy PBKDF2, 5 failures → 15-minute lock |
| V-10 | Passwords, tokens, note bodies and SQL details in errors/logs | Safe `AppError` messages and redacted audit metadata |
| V-11 | No meaningful field/file limits | Username/password/title/body/tag/search/import/filename bounds; control-character checks |

The full reasoning, exploit walkthroughs, alternatives and residual risks are
in [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md).

## Architecture

```text
CLI (argparse + getpass)
    │
    ├── AuthService ───── validation ─── PBKDF2 / sessions / lockout
    │                                └── password-derived Fernet context
    └── NoteService ───── owner-scoped SQL + encryption + safe files
                                     │
SQLite: users │ sessions(token_hash) │ notes(ciphertext) │ audit_events
```

Important invariants:

- A note operation requires an in-memory `AuthContext` created from a correct
  password; the Fernet key is not stored in SQLite.
- Password verification and note-key derivation use **separate salts**, so the
  stored password verifier is not the encryption key.
- Every note query includes the authenticated user's ID as a bound parameter.
- Search is literal in memory after owner-scoped decryption; search text is
  never SQL.
- File-producing operations accept only safe basenames inside controlled
  directories.
- Audit records contain event/outcome/user/note-ID metadata, never passwords,
  tokens, titles or bodies.

## Project structure

```text
.
├── README.md
├── SUBMISSION_DESCRIPTION.md
├── run.py
├── pyproject.toml
├── requirements*.txt
├── securenotes/
│   ├── audit.py
│   ├── auth.py
│   ├── cli.py
│   ├── crypto.py
│   ├── db.py
│   ├── errors.py
│   ├── service.py
│   └── validation.py
├── vulnerable/
│   ├── README_WARNING.md
│   └── vulnerable_app.py       # quarantined audit baseline only
├── tests/
│   ├── test_attack_simulations.py
│   ├── test_auth_security.py
│   ├── test_cli.py
│   ├── test_crypto.py
│   └── test_notes_security.py
├── tools/
│   ├── attack_demo.py
│   └── generate_evidence.py
├── examples/demo.py
├── data/sample_import.json
├── docs/
│   ├── SECURITY_AUDIT.md
│   ├── THREAT_MODEL.md
│   ├── TESTING_AND_ATTACKS.md
│   ├── EVIDENCE_INDEX.md
│   ├── WORK_LOG.md
│   ├── GITHUB_UPLOAD_GUIDE.md
│   └── evidence/figures/
└── results/
    ├── security_summary.json
    └── security_scans/
```

## Documentation map

- [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md) — complete vulnerability
  register and one deep section per finding.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — assets, actors, trust
  boundaries, STRIDE analysis, assumptions and abuse cases.
- [`docs/TESTING_AND_ATTACKS.md`](docs/TESTING_AND_ATTACKS.md) — test design,
  attack methodology, Bandit scope/triage and worked cases.
- [`docs/EVIDENCE_INDEX.md`](docs/EVIDENCE_INDEX.md) — every transcript,
  Figure and machine-readable result.
- [`docs/WORK_LOG.md`](docs/WORK_LOG.md) — process sequence, mistakes found
  during verification, and design trade-offs.
- [`docs/GITHUB_UPLOAD_GUIDE.md`](docs/GITHUB_UPLOAD_GUIDE.md) — root-level
  upload and staged-commit instructions.

## Known limits — read before using with real data

SecureNotes is a teaching project, not a certified password manager.

- **Forgotten password = unrecoverable notes.** There is no backdoor or
  recovery key; the decryption key is derived from the password.
- A compromised running process/OS account can observe plaintext while the
  user is authenticated. Encryption at rest does not solve endpoint compromise.
- JSON exports are plaintext by design.
- A whole-database backup remains an operator-level artefact: it contains all
  users' ciphertext and password verifiers, so protect it as sensitive.
- Account lockout can be abused to deny service to a known username; this is
  the standard confidentiality/availability trade-off.
- Search decrypts the current user's notes in memory. That is simple and safe
  for this local scope but would need a different design at large scale.
- Local timestamps, note counts and ciphertext length
