# Security Policy

SecureShare is an academic lab project for CYC386 (COMSATS University
Islamabad). It intentionally ships a documented, historical record of
five vulnerability classes (see `docs/SECURITY_IMPLEMENTATION.md`) in its
git history (`vulnerable-baseline` tag) for educational purposes. **The
current `main` branch / `secure-release` tag has all five fixed** — do
not deploy any commit prior to the relevant `fix/*` merge outside an
isolated lab environment.

## Supported Versions

| Version / tag | Supported |
|---|---|
| `secure-release` and later on `main` | ✅ Security fixes apply here |
| `vulnerable-baseline` and intermediate `fix/*` branch tips | ❌ Intentionally vulnerable / in-progress — lab use only |

## Reporting a Vulnerability

This is a course project, not a production service. If you are a
classmate, grader, or instructor and find an issue beyond the five
documented vulnerability classes:

1. **Do not** open a public GitHub issue with exploit details.
2. Email the team (see repository contributors) or contact the course
   instructor, Engr. Muhammad Ahmad Nawaz (m.ahmadnawazz@gmail.com),
   directly with:
   - A description of the issue and affected endpoint/file.
   - Steps to reproduce (lab-only, against your own local instance).
   - Suggested severity (see `docs/THREAT_MODEL.md` for our CVSS v3.1
     scoring methodology, reused here for consistency).
3. We will acknowledge within 48 hours and, if valid, add a new
   `fix/<name>` branch, a regression test, and update
   `docs/SECURITY_IMPLEMENTATION.md` following the same pattern as the
   five mandatory classes.

## Known, Accepted Limitations (Residual Risk)

See `docs/THREAT_MODEL.md` §7 ("Residual Risk Statement") for the full,
explicit list (e.g. no login rate-limiting, no per-user storage quota,
SQLite used instead of a production database). These are documented,
deliberate scope decisions for a one-week academic sprint — not
oversights.

## Secrets

`app.config["SECRET_KEY"]` has a **development-only fallback** value in
`app/app.py`. Set a real `SECRET_KEY` environment variable before any
non-local use:
```bash
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```
Never commit a real `SECRET_KEY`, database file, or `.env` to this
repository (see `.gitignore`).
