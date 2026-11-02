# GitHub upload guide — avoid the nested-folder problem

## The one rule

Upload the **contents** of this project to the repository root. Do not upload
a folder named `week5_security_enhancements` inside the repository.

Correct repository landing page:

```text
README.md
run.py
securenotes/
tests/
docs/
tools/
vulnerable/
results/
```

Incorrect landing page:

```text
README.md                         <- copied duplicate
week5_security_enhancements/      <- actual project hidden one level down
```

The README commands assume the first layout. They intentionally do not say
`cd week5_security_enhancements`.

## Recommended method: Git command line with staged commits

### 1. Create the empty GitHub repository

Create a public repository named, for example:

```text
week5_security_enhancements
```

Do **not** tick “Add a README”, “Add .gitignore” or “Choose a license” during
creation. This project already supplies its README and `.gitignore`; starting
empty avoids an unrelated first commit/merge.

### 2. Extract the GitHub-root ZIP

Use the archive whose files are at the top level (not the conventional
submission ZIP that contains a project folder). Open a terminal in the
extracted directory. Confirm you can see `run.py` and `README.md` immediately:

```bash
ls
```

### 3. Initialise and connect the repository

Replace the URL with the actual empty repository URL:

```bash
git init
git branch -M main
git remote add origin https://github.com/Vaibhav41-cmd/week5_security_enhancements.git
```

### 4. Commit in logical stages

The following five commits show the security-engineering sequence instead of
one bulk “first commit”. Run `git status` between stages if unsure.

#### Commit 1 — project setup and quarantined baseline

```bash
git add .gitignore pyproject.toml requirements.txt requirements-dev.txt requirements-evidence.txt data vulnerable
git commit -m "chore: add project setup and quarantined vulnerable baseline"
```

#### Commit 2 — hardened application

```bash
git add run.py securenotes
git commit -m "feat: implement hardened SecureNotes application"
```

#### Commit 3 — tests and attack harness

```bash
git add tests examples tools/attack_demo.py
git commit -m "test: add security regression and baseline attack simulations"
```

#### Commit 4 — generated evidence and audit documentation

```bash
git add tools/generate_evidence.py results docs
git commit -m "docs: add security audit threat model and verification evidence"
```

#### Commit 5 — landing page and submission text

```bash
git add README.md SUBMISSION_DESCRIPTION.md
git commit -m "docs: add project guide and Week 5 submission description"
```

Confirm nothing important is left behind:

```bash
git status --short
```

Only ignored caches/local data should remain untracked or absent.

### 5. Push

```bash
git push -u origin main
```

## Alternative: GitHub web upload in batches

If using the browser:

1. Extract the **GitHub-root** ZIP.
2. Open the extracted folder so `README.md`, `run.py`, `securenotes/`, etc. are
   visible.
3. In the empty GitHub repo choose **uploading an existing file**.
4. Drag in only the first batch from Commit 1 above. Do not drag the parent
   folder.
5. Use the same meaningful commit message.
6. Repeat with **Add file → Upload files** for Commits 2–5.
7. After the final batch, check the landing page tree. There must not be a
   `week5_security_enhancements/` directory inside the repository.

## Fresh-clone verification

Do this before submitting the GitHub URL. In a new temporary folder:

```bash
git clone https://github.com/Vaibhav41-cmd/week5_security_enhancements.git
cd week5_security_enhancements
python -m pip install -r requirements.txt -r requirements-dev.txt -r requirements-evidence.txt
python -m pytest -q
python examples/demo.py
python tools/attack_demo.py
bandit -r securenotes
```

Expected:

- `58 passed`;
- workflow ends by decrypting Alice's note after password rotation;
- attack table shows baseline exploited/exposed and hardened
  blocked/protected;
- secure Bandit reports no issues.

Also click these links from the GitHub landing page:

- `docs/SECURITY_AUDIT.md`
- `docs/THREAT_MODEL.md`
- `docs/EVIDENCE_INDEX.md`

Their figures should render because all paths are relative to the repository
root/document location.

## If the wrong nested layout was already uploaded

The cleanest correction for a new submission repository is to create the
repository afresh or remove the nested tree and recommit the contents at root.
Do not solve it by copying the project README to the root while leaving code
one level down: that was the earlier failure mode, because the copied README's
commands and links assume that its own directory is the project root.
