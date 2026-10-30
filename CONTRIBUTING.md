# Contributing / Team Workflow

This document records the Git/GitHub workflow used by the SecureShare
team for the CYC386 Midterm Lab Exam sprint (CDF §6.1).

## Branching Strategy

- **`main`** — protected. No direct pushes. Only updated via a merged,
  reviewed Pull Request. Represents the current best-known-secure state.
- **`feature/<name>`** — new functionality (e.g. `feature/scaffold`,
  `feature/ci-cd`).
- **`fix/<name>`** — a bug or vulnerability fix, **one vulnerability
  class per branch** (e.g. `fix/idor`, `fix/csrf`, `fix/clickjacking`,
  `fix/command-injection`, `fix/buffer-overflow`), so each fix's diff,
  commit message, and regression test are independently reviewable and
  revertible.
- **`chore/<name>`** — non-functional maintenance (e.g.
  `chore/sast-triage`).

## Pull Request / Review Process

1. Branch off `main`.
2. Make the change; add/update tests in `tests/` for anything
   security-relevant.
3. Run locally before opening a PR:
   ```bash
   python -m pytest tests/ -v
   bandit -r app/ -lll -iii
   semgrep --config=auto app/ --severity=ERROR --error
   pip-audit -r requirements.txt
   ```
4. Open a PR into `main` with a description following the pattern used
   throughout this repo's history: what changed, which CWE/vulnerability
   it addresses (if applicable), and how it was verified.
5. **At least one other team member reviews and approves** before merge
   (CDF requirement: "at least one peer review per PR"). For this
   two-person team, Syed Zurriat Hussain and Muhammad Ahmadd
   cross-reviewed each other's fix branches — see each merge commit
   message for the named reviewer.
6. Merge with `--no-ff` (a real merge commit, not a fast-forward) so the
   branch structure and PR boundary stay visible in `git log --graph`.
7. Delete the feature/fix branch after merge (kept in this academic repo
   for grading traceability; in a normal project these would be deleted).

## Commit Message Convention

```
<type>(<scope>): <short summary>

<body: what changed, why, what CWE/vulnerability it fixes if applicable,
what tests verify it>

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
```
Types used in this repo: `feat`, `fix`, `chore`.

## Traceability (PNE → Threat → Fix → Test)

Every fix branch in this repo traces back through:
1. A protection need in `docs/PNE_Report.md` (§4, PN1-PN10).
2. A threat in `docs/THREAT_MODEL.md` (STRIDE table §3, scored in §5).
3. The fix commit (table in `README.md` "Git Workflow").
4. A regression test in `tests/` (listed per-vulnerability in
   `docs/SECURITY_IMPLEMENTATION.md`).

This chain is also mirrored in the Jira sprint board (Epics → Stories →
Tasks), with each Story linking back to its PNE item and STRIDE threat
ID, per the sprint's required traceability.

## Code Style

- Python: standard library + Flask idioms, docstrings on non-obvious
  functions, comments explaining *why* on every security-relevant line
  (see `app/app.py` for the pattern — every fix is commented with what
  it replaces and why).
- C: comments on every unsafe-vs-safe pattern (see `native/parser.c` vs
  `native/parser_fixed.c`).
- No secrets, credentials, or real personal data in commits — this repo
  uses clearly-labeled lab/demo credentials only (`alice`/`bob`).
