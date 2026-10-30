# SecureShare

A minimal Flask file-sharing web app, built as the lab target for
**CYC386 — Secure Software Design and Development** (Midterm Lab Exam,
Fall 2026, COMSATS University Islamabad).

**Team:** Syed Zurriat Hussain (FA23-BCT-041), Muhammad Ahmadd (FA23-BCT-020), Junaid (FA23-BCT-057)
**Repository:** https://github.com/ZuriAtSyed/SecureApp-Sprint-Zurriat-Ahmad-Junaid

[![CI/CD](https://github.com/ZuriAtSyed/SecureApp-Sprint-Zurriat-Ahmad-Junaid/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/ZuriAtSyed/SecureApp-Sprint-Zurriat-Ahmad-Junaid/actions/workflows/ci-cd.yml)

SecureShare was first built as an intentionally vulnerable baseline
(tag [`vulnerable-baseline`](../../tree/vulnerable-baseline)) containing
all five mandatory vulnerability classes, then hardened across five
dedicated fix branches into the current, secure state (tag
[`secure-release`](../../tree/secure-release)). See
[`docs/SECURITY_IMPLEMENTATION.md`](docs/SECURITY_IMPLEMENTATION.md) for
the full before/after story of each vulnerability.

## Documentation Index

| Document | Contents |
|---|---|
| [`docs/PNE_Report.md`](docs/PNE_Report.md) | Asset inventory, stakeholders, protection needs, CIA-triad mapping |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Context + Level-1 DFDs, STRIDE analysis, 2 attack trees, CVSS v3.1 scoring, risk register, residual risk |
| [`docs/SECURITY_IMPLEMENTATION.md`](docs/SECURITY_IMPLEMENTATION.md) | Per-vulnerability: vulnerable code, PoC + screenshots, fix, verification |
| [`docs/SECURITY_TEST_REPORT.md`](docs/SECURITY_TEST_REPORT.md) | SAST (Bandit, Semgrep), dependency audit (pip-audit), DAST (OWASP ZAP) — before/after |
| [`SECURITY.md`](SECURITY.md) | Vulnerability disclosure policy |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Branching, PR, and review workflow used for this sprint |
| [`Screenshots/`](Screenshots/) | 12 numbered screenshots: exploit evidence (01-08) and fixed-state evidence (09-12) |

## Architecture

```
SecureApp-Sprint-ZurriatAhmad/
├── app/
│   ├── app.py            # Flask application (routes, auth, authZ)
│   ├── seed_demo.py       # Creates alice/bob demo accounts + files
│   ├── templates/         # Jinja2 templates
│   ├── uploads/            # User-uploaded files (gitignored)
│   └── exports/            # Server-side export copies (gitignored)
├── native/
│   ├── parser.c            # Buffer-overflow-vulnerable helper (kept as the "before" artifact)
│   ├── parser_fixed.c       # Remediated helper (bounds-checked)
│   └── Makefile
├── tests/                  # pytest regression suite (one file per vulnerability class)
├── docs/                   # PNE, threat model, implementation & test reports
├── Screenshots/             # Exploit + fix evidence
└── .github/workflows/ci-cd.yml   # Build → test → SAST → DAST pipeline
```

## Prerequisites

- Python 3.10+
- `gcc` (to build the native metadata parser)
- `pip`

## Build & Run

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Build the native metadata-parser helper (production/fixed build)
cd native && make parser_fixed && cd ..

# 3. Seed demo accounts (alice/AlicePassw0rd!, bob/BobPassw0rd!)
cd app && python3 seed_demo.py && cd ..

# 4. Run the app
cd app && python3 app.py
# -> http://127.0.0.1:5000
```

## Run the Tests

```bash
pip install pytest
python -m pytest tests/ -v
```
11 tests, 2 per vulnerability class (one proving the attack is blocked,
one proving the legitimate flow still works) plus one extra IDOR
"owner can view own file" control.

## Reproduce the Security Scans

```bash
pip install bandit semgrep pip-audit
bandit -r app/ -lll -iii            # SAST — fails (non-zero) on High/Critical
semgrep --config=auto app/ --severity=ERROR --error   # SAST — fails on ERROR severity
pip-audit -r requirements.txt       # Dependency CVE audit — fails on any known CVE
```
All three exit `0` against the current (`secure-release`) code. See
[`docs/SECURITY_TEST_REPORT.md`](docs/SECURITY_TEST_REPORT.md) for full
before/after results, including a DAST (OWASP ZAP) pass.

## Git Workflow

- `main` — protected; only updated via merged PRs (see `CONTRIBUTING.md`).
- `feature/*`, `fix/*`, `chore/*` — one branch per unit of work, one
  vulnerability fix per `fix/*` branch.
- Tags: `vulnerable-baseline` (pre-fix state, for the before/after story)
  and `secure-release` (all five fixes + SAST triage + dependency fix
  merged).

| Branch | Purpose | Merge commit |
|---|---|---|
| `feature/scaffold` | Vulnerable baseline app + native helper | `d18facb` |
| `fix/idor` | Object-level authorization (CWE-639) | `ac157b3` |
| `fix/csrf` | Flask-WTF CSRFProtect + SameSite cookies (CWE-352) | `7de12b7` |
| `fix/clickjacking` | X-Frame-Options + CSP frame-ancestors | `fafb511` |
| `fix/command-injection` | Removed `shell=True`, allow-listed input (CWE-78) | `33561c4` |
| `fix/buffer-overflow` | Bounds-checked native parser (CWE-121) | `a14c0a7` |
| `chore/sast-triage` | Triaged remaining Semgrep false positives | `4f70bc4` |
| `fix/dependency-werkzeug` | Resolved 7 known Werkzeug CVEs | `26a9141` |
| `chore/csp-hardening` | Strict CSP (all directives locked to `'self'`) from DAST findings | `2742df6` |

## Demo Accounts (lab only — never use these patterns in production)

| User | Password | Owns |
|---|---|---|
| `alice` | `AlicePassw0rd!` | `payroll_notes.txt` (used as the "victim" file in the IDOR/CSRF PoCs) |
| `bob` | `BobPassw0rd!` | `notes.txt` (used as the "attacker's own" file for the command-injection PoC) |

## License

Academic project for CYC386, COMSATS University Islamabad. Not licensed
for external use.
