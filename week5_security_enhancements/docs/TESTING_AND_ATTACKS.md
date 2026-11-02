# Testing and attack-simulation guide

## Purpose

This document explains how the Week 5 result was verified. The testing goal
was stricter than “the secure tests pass”:

1. prove the baseline weakness is actually reachable;
2. run the same hostile input against the hardened design;
3. show the legitimate version of that feature still works;
4. retain enough transcript/scan evidence for another reviewer to reproduce
   the conclusion.

That structure matters because a broken login page would also “block” SQL
injection. A security fix has value only when normal users can still log in,
search, import and back up.

## Test environment

The final evidence was generated with:

- Python 3.13.16;
- pytest 9.0.3;
- Bandit 1.9.4;
- cryptography 50.0.2;
- Linux sandbox used for the internship workspace.

The checked-in environment transcript is `docs/evidence/environment.txt`.
Tests use temporary SQLite databases and directories. Synthetic passwords and
note bodies are used throughout.

## How to run everything

From the repository root:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt -r requirements-evidence.txt
python -m pytest -vv
python tools/attack_demo.py
bandit -r vulnerable/vulnerable_app.py
bandit -r securenotes
python examples/demo.py
python tools/generate_evidence.py
```

Expected headline results:

```text
58 passed
Baseline Bandit: 7 issues (1 Low, 4 Medium, 2 High)
Secure Bandit:   0 unsuppressed issues
Attack demo:     13/13 baseline rows exploitable/exposed
                 13/13 hardened rows blocked/protected
                 2/2 legitimate workflow rows succeed
```

`tools/generate_evidence.py --reuse-test-output` exists only to redraw figures
from an existing successful evidence set. The normal command performs fresh
runs.

## Test inventory

| File | Collected | What it proves |
|---|---:|---|
| `tests/test_attack_simulations.py` | 9 | The quarantined baseline really is exploitable |
| `tests/test_auth_security.py` | 17 | Registration, authentication, lockout, sessions, rotation and audit redaction |
| `tests/test_cli.py` | 2 | CLI register/add flow and hidden session-token prompt |
| `tests/test_crypto.py` | 4 | PBKDF2 records, tamper failure, Fernet key separation and token digests |
| `tests/test_notes_security.py` | 26 | Note CRUD, IDOR, search, raw database, input bounds, import/export/backup, permissions |
| **Total** | **58** |  |

Markers (overlapping by design):

- `attack`: 9 tests; the expected result is a *successful* exploit against the
  quarantined file.
- `security`: 44 tests/cases; attacks should be blocked or a control invariant
  should hold.
- `functionality`: 6 tests/cases; normal behaviour after hardening.

Run a group with, for example:

```bash
python -m pytest -m "attack" -q
python -m pytest -m "security" -q
python -m pytest -m "functionality" -q
```

## Testing strategy by layer

### 1. Cryptographic invariants

These tests do not attempt to prove the mathematics of PBKDF2 or Fernet. They
verify the application's use of the primitives:

- password records are self-describing and independently salted;
- the iteration count is at least 600,000;
- correct/wrong passwords behave correctly;
- a one-character tamper of the stored verifier fails;
- a Fernet key derived from the wrong password cannot decrypt;
- session tokens are long, distinct and represented by a 64-character SHA-256
  hex digest in storage design.

### 2. Authentication and session behaviour

Cases include:

- username normalization and duplicate rejection;
- four forms of weak password;
- unknown user versus wrong password message equality;
- three login injection forms;
- exactly five failures leading to lockout;
- an expired lock clearing;
- token-hash storage, validation, expiry and revocation;
- password rotation revoking an old session and re-encrypting a note.

### 3. Authorization and data confidentiality

Two accounts are created so the tests can distinguish “not logged in” from
“logged in as the wrong person.” Bob attempts to read, update and delete
Alice's note. All three return `NotFoundError`, and Alice's original title is
unchanged.

The raw-storage test searches database, WAL and SHM bytes for:

- a distinctive title;
- a distinctive body;
- a password substring.

That is stronger than only querying SQLite columns, because plaintext left in
a WAL sidecar would be caught.

### 4. Input and filesystem abuse

Parameterization (in the pytest sense) is used where one rule has several
hostile spellings:

- four search payloads, including `%`, `_` and a DROP TABLE string;
- traversal using Unix, Windows and absolute path forms;
- extra-key, wrong-type and non-list JSON schemas;
- oversized title/body/tag/search/import values;
- a terminal escape sequence in a note body;
- a shell separator inside a backup filename;
- a pickle extension and an import larger than 1 MB.

### 5. End-to-end workflow

The CLI test mocks `getpass` but calls the real `main()` argument parser,
database, authentication, encryption and note creation. It proves the pieces
compose without requiring an interactive terminal in CI.

`examples/demo.py` is not a substitute test; it is a human-readable workflow
transcript using the same service layer. It prints:

- two registrations and a redacted token;
- creation/list/search;
- Bob's denied read;
- truncated ciphertext values;
- an owner-only export;
- password rotation and successful decryption under the new password.

## Paired attack harness

### Design

`tools/attack_demo.py` creates separate temporary directories for baseline and
hardened runs. It seeds both with an Alice account and a note containing the
synthetic marker `SYNTHETIC-SECRET`, then applies equivalent scenarios.

| ID | Hostile/observable action | Safe proof used |
|---|---|---|
| V-01a | Login as `alice' --` with wrong password | Whether a session is issued |
| V-01b | Search with `' ) OR 1=1 --` | Whether another user's note is returned |
| V-02 | Inspect password verifier | Exact MD5 vs PBKDF2 format/iterations |
| V-03 | Read Alice's note as another identity | Returned body vs `NotFoundError` |
| V-04 | Search raw DB bytes | Boolean plaintext presence |
| V-05 | Inspect token/storage | Predictable raw value vs digest equality |
| V-06 | Import pickle canary | Harmless marker file |
| V-07 | Export `../escaped.*` | File created outside intended directory |
| V-08 | Backup name with `; touch ...` | Harmless marker file |
| V-09a | Unknown vs wrong-password login | Public messages |
| V-09b | Five wrong + one correct password | Lock message |
| V-10 | Inspect logs/audit text | Secret substring presence/absence |
| V-11 | 20,000-character body | Stored vs validation error |
| F-01 | Alice reads her note | Plaintext equality after decryption |
| F-02 | Safe backup filename | Backup exists |

The full generated output is in `docs/evidence/attack_demo.md`.

### Why harmless markers?

For pickle and command injection, simply observing an exception is not enough:
the question is whether attacker-chosen code ran. A `touch marker` side
effect gives a binary, externally observable answer without destructive or
network behaviour. The marker path is inside a temporary test directory.

## Three worked test cases in detail

### Case A — SQL injection payload had to match the actual query grammar

The baseline search query has this shape:

```sql
WHERE user_id = <id>
  AND (title LIKE '%<query>%' OR body LIKE '%<query>%')
```

An initial payload `' OR 1=1 --` commented out the remainder, leaving an
unclosed parenthesis, and a second attempt stayed trapped behind
`user_id = 999 AND (...)` due to operator precedence. The working payload is:

```text
' ) OR 1=1 --
```

It closes the string and parenthesised group, then adds an always-true
top-level `OR`, and comments out the rest. This is a stronger audit result
than a generic copied payload because it demonstrates the exact parse-tree
change. In the hardened app, the string is only a literal substring searched
within Bob's own decrypted notes, so it returns zero Alice notes.

### Case B — IDOR test asserts data integrity, not just an exception

A weak test might assert only that Bob receives an error on read. SecureNotes
also verifies attempted update and delete. After Bob's three attempts, Alice
reads her note and its title is still the original. That catches a subtle
partial-fix in which read is owner-scoped but update/delete remain global.

### Case C — Password rotation checks both secrecy and availability

Password change crosses password verifier, key salt, every note ciphertext and
all sessions. Its test sequence is:

1. Alice creates a note under password A.
2. Change to password B.
3. Alice's old session no longer validates.
4. Password A no longer authenticates.
5. Password B authenticates.
6. The original note body decrypts exactly.

If re-encryption were skipped, step 6 would fail. If sessions were retained,
step 3 would fail. The test therefore guards the complete design, not just the
password-hash update.

## Bandit methodology

Commands used by `tools/generate_evidence.py`:

```bash
bandit -r vulnerable/vulnerable_app.py -f json -o results/security_scans/bandit_baseline.json
bandit -r vulnerable/vulnerable_app.py -f txt  -o results/security_scans/bandit_baseline.txt
bandit -r securenotes                  -f json -o results/security_scans/bandit_secure.json
bandit -r securenotes                  -f txt  -o results/security_scans/bandit_secure.txt
```

### Baseline mapping

| Rule | Count | Audit ID |
|---|---:|---|
| B608 hard-coded SQL | 3 | V-01 |
| B324 MD5 | 1 | V-02 |
| B403 pickle import | 1 | V-06 |
| B301 pickle call | 1 | V-06 |
| B605 shell | 1 | V-08 |

### Findings Bandit could not decide

The following needed semantic/manual review:

- V-03 owner authorization;
- V-04 whether note fields are sensitive and encrypted;
- V-05 token form/expiry/storage contract;
- V-07 resolved-path containment;
- V-09 response equivalence and lockout policy;
- V-10 which log fields are secrets;
- V-11 product-specific size limits.

### Triage example

Bandit's B105 rule proposed “possible hard-coded password” for
`PASSWORD_ALGORITHM = "pbkdf2_sha256"`. The reviewer disposition is recorded
in code and the audit report: it is a public algorithm identifier, not a
secret. Only that line is suppressed. This models correct scanner use:
investigate, document, suppress narrowly—do not ignore an entire rule or
change a harmless constant merely to make a dashboard green.

### Why tests/tools are not the production scan target

The test suite intentionally creates a pickle canary and uses `assert`;
Bandit therefore reports expected test-code items such as B101/B403 and
synthetic password constants. Those are useful awareness results, but they do
not describe the deployed package. The production decision uses `securenotes/`
and keeps the quarantined baseline as a separate scan.

## Evidence quality checks

Before packaging, the evidence set is checked for:

- the printed test total in the summary, README, audit and report matching;
- Bandit totals matching the JSON files;
- Figure numbering matching captions/links;
- no real password/token in transcripts;
- machine workspace paths replaced by `<project-root>` in displayed output;
- a fresh extraction/clone running tests and demos from the repository root;
- ZIP contents excluding caches, virtual environments, live databases and
  temporary exports.

## Limitations of this verification

- Tests demonstrate selected payloads and invariants; they are not a formal
  proof that no other vulnerability exists.
- There is no fuzzing campaign or large-scale performance/DoS test. Input
  bounds are unit-tested at representative boundaries.
- POSIX file-mode assertions are conditional; Windows ACL behaviour is not
  modelled by mode bits.
- The CLI prompts are mocked in automated tests, so exact terminal echo
  behaviour depends on Python's `getpass` implementation and terminal.
- Password timing is reduced with dummy PBKDF2 but not measured as a formal
  side-channel experiment.
- The attack app and secure app are separate implementations of the same
  feature concept; tests compare observable security behaviour rather than
  asserting identical internal APIs.
