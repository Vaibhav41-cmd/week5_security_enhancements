# Week 5 work log and design journal

This log records the sequence of work and, importantly, the points where an
initial idea or test was wrong. The aim is to show the engineering process
rather than only the polished final directory.

## Phase 1 — Choose a scope that could be audited end to end

### Decision

Build a local notes CLI rather than a web application.

### Reasoning

The brief allowed a basic web **or CLI** application. A notes CLI still has
the important data flows—authentication, sensitive content, SQL, files,
imports, backups and logs—but avoids spending the security week on web
framework boilerplate. Keeping the scope local also made it safe to retain a
vulnerable baseline and run exploit demonstrations only against temporary
databases.

### Consequence

The threat model focuses on local users, stolen files, hostile filenames and
malicious import content. Network issues such as TLS, CSRF and browser XSS are
explicitly out of scope rather than being claimed without an implementation.

## Phase 2 — Preserve a vulnerable “before” implementation

### Work completed

Created `vulnerable/vulnerable_app.py` with a deliberately unsafe version of
the same feature concept:

- interpolated SQL;
- MD5 password storage;
- unscoped note lookup;
- plaintext notes;
- predictable raw session values;
- pickle import;
- traversal-prone export;
- shell backup;
- enumeration-friendly errors;
- secret-bearing logs;
- no practical input policy.

### Safety decision

The file was placed in a separate directory with `README_WARNING.md`, is not
imported by `run.py` or the secure package, and is used only by attack tests
and the attack harness.

## Phase 3 — Audit manually before trusting the scanner

### Work completed

Traced inputs through the baseline:

```text
username/password -> SQL/users
note ID          -> authorization
note text        -> DB/logs/display
search query     -> SQL
filename         -> filesystem/shell
import file      -> deserializer
session token    -> DB/logs
```

This produced the 11-item vulnerability register. Bandit was then run as a
second lens. It confirmed SQL construction, MD5, pickle and shell execution,
but could not know the ownership rule or decide which log contents were
secrets.

### Lesson recorded

Static analysis is excellent at recognizable dangerous constructs; it is not
a substitute for a threat model and authorization review.

## Phase 4 — Prove the attacks

### Initial problem found

The first two search-injection strings I tried did not actually expose
Alice's note:

1. one commented out a closing parenthesis and made SQL incomplete;
2. another remained inside `user_id = 999 AND (...)`, so operator precedence
   kept the result empty.

The working string, `' ) OR 1=1 --`, closes the literal/group and adds the
always-true condition at the top level.

### Why this mattered

Copying a famous `"OR 1=1"` string would have made the audit look superficial
and the regression test meaningless. Deriving the exact payload from the
query grammar made the baseline proof and hardened comparison credible.

### Other proof techniques

- A recognizable synthetic secret was searched in raw DB/WAL bytes.
- Pickle and shell attacks used harmless temporary marker files.
- Session predictability was shown by bracketing the login time and comparing
  the token with the raw database value.
- Message strings were compared directly for enumeration.

## Phase 5 — Implement the hardened architecture

### Main design choices

1. **Separate modules by responsibility:** validation, cryptography, database,
   authentication, notes, audit and CLI.
2. **Parameterized SQL as an invariant:** validation does not replace bound
   parameters.
3. **Authorization in queries:** note operations always include owner ID.
4. **Two password-derived outputs, different salts:** stored verifier and
   memory-only note key are separated.
5. **Remove interpreters where possible:** JSON replaces pickle; SQLite's
   backup API replaces the shell.
6. **Fail safely:** foreign/missing notes and authentication failures avoid
   information-revealing distinctions.
7. **Audit metadata, not content:** logs should help review without becoming
   another secret store.

### Functionality retained

Registration, login/session validation, note CRUD/search, JSON import/export,
backup and password change all remained available. Password change required
re-encryption; simply changing the verifier would have locked the user out of
existing notes.

## Phase 6 — Test the secure and insecure directions

### Test design

- Baseline attack tests assert exploit success, making the “before” claim
  executable.
- Secure tests assert the payload fails.
- Separate functionality tests assert Alice can still do the legitimate task.

### Failure/fix cycle during test authoring

The first full run exposed mismatches between my test assumptions and the
baseline helper API (method names and the dynamic timestamp in its token).
Those failures were in the demonstration harness, not evidence that the
baseline was safe. The tests were corrected to:

- call the actual baseline methods;
- treat the timestamp as a bracketed current-second value;
- inspect the raw session in SQLite;
- use the exact CLI success wording.

This cycle is retained here because it illustrates why attack code itself
needs review.

## Phase 7 — Code-review hardening beyond the original 11 items

A review of the hardened implementation found smaller issues that were fixed
before packaging:

1. **Session token in shell history:** `whoami`/`logout` originally required
   `--token`. They now use a hidden prompt when the option is omitted.
2. **Directory-permission side effect:** creating a database could tighten an
   existing parent directory. SecureNotes now tightens a parent only when it
   created that directory; the database file itself is still 0600 on POSIX.
3. **Terminal escape text:** note bodies now reject control characters other
   than tab/newline/carriage return, so imported ANSI escapes cannot manipulate
   the terminal when displayed.
4. **Permission race:** exports and backups are created owner-only before
   sensitive content is written, rather than relying solely on chmod later.
5. **Readable evidence:** a pytest parameter originally expanded a
   10,001-character body into the test ID. Explicit IDs such as
   `body-too-long` make the transcript readable.

These additions did not change the 11-finding register; they demonstrate
defence-in-depth review of the replacement code.

## Phase 8 — Scanner triage

### Baseline

Bandit reported 7 issues mapped to V-01, V-02, V-06 and V-08.

### Secure package

One B105 candidate flagged:

```python
PASSWORD_ALGORITHM = "pbkdf2_sha256"
```

I treated this as a false positive because it is a public algorithm label,
not a password. The suppression is limited to that line and includes a reason.
The final secure scan has zero unsuppressed findings.

## Phase 9 — Evidence and reporting

### Evidence strategy based on previous evaluator feedback

Earlier weekly feedback favoured more concrete examples and clearer
formatting over sheer listing volume. Week 5 therefore uses:

- three detailed worked cases (SQL grammar, IDOR integrity, password
  rotation);
- an 11-row before/after matrix;
- fewer, larger figures;
- short curated code extracts tied to a design point;
- full code in the repository rather than dumping every file into the Word
  report;
- a separate audit document where every finding has impact, rationale,
  evidence and residual risk.

### Packaging strategy

Two ZIP forms are prepared:

1. a conventional submission archive containing the project folder;
2. a GitHub-root archive whose contents extract directly at repository root.

The latter directly addresses the previous nested-folder problem: README
commands and relative links all assume the repository root contains
`run.py`, `securenotes/`, `docs/` and `tests/` directly.

## Final verification checklist

- [x] Vulnerable baseline isolated and warned
- [x] 11 vulnerabilities documented with CWE/severity
- [x] 13 attack-demo vulnerability rows reproduced on baseline
- [x] 13/13 blocked or protected after hardening
- [x] 58 automated tests passing
- [x] Bandit before/after reports generated
- [x] Legitimate workflow and backup proof included
- [x] Threat model and evidence index written
- [x] Fresh-extraction verification completed for both the conventional and GitHub-root archives (58 tests, demo, attack harness, Bandit and CLI help)

## Reflection

The most transferable lesson from Week 5 is to ask, for every input,
**“which interpreter or trust boundary will consume this?”** A value that is
harmless text in one context becomes SQL in a query string, a path in a
filesystem join, a program in pickle, or a command in a shell. Most fixes follow
from keeping data in the data plane: bind it, validate its contract, scope it
to an owner, encrypt it before storage, or remove the dangerous interpreter.
