# WARNING — intentionally vulnerable teaching baseline

`vulnerable_app.py` is **not** the submitted secure application. It is a small,
quarantined "before" implementation retained only so that the audit can prove
the impact of each weakness locally and compare the same attack against the
hardened `securenotes/` package.

Do not deploy it, expose it on a network, copy its patterns, or use real
passwords/notes with it. The secure application is started from the project
root with `python run.py ...`.
