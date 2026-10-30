# Protection Needs Elicitation (PNE) Report
**Project:** SecureShare — File Sharing / Collaboration Platform
**Course:** CYC386 — Secure Software Design and Development, Midterm Lab Exam
**Team:** Syed Zurriat Hussain (FA23-BCT-041), Muhammad Ahmadd (FA23-BCT-020), Junaid (FA23-BCT-057)
**Institution:** COMSATS University Islamabad, Department of Computer Science
**Date:** 2026-10-30

---

## 1. System Overview

SecureShare is a minimal Flask-based file-sharing web application. Authenticated
users upload files, view their own file listing, inspect a file's metadata
(parsed by a native C helper), download their files, export copies under a
chosen name, and delete files they own. It is the lab target for this sprint's
mandatory vulnerability classes (IDOR, CSRF, Clickjacking, Command Injection,
Buffer Overflow), built intentionally vulnerable first (tag `vulnerable-baseline`)
and then hardened across five fix branches (tag `secure-release`).

## 2. Asset Inventory

| # | Asset | Type | Description |
|---|-------|------|--------------|
| A1 | User credentials (`users.password_hash`) | Data | Salted/hashed passwords (Werkzeug `generate_password_hash`) |
| A2 | Session cookie | Data / token | Flask signed session cookie identifying the logged-in user |
| A3 | Uploaded files (`app/uploads/`) | Data | User-owned file content, may be confidential (e.g. payroll notes) |
| A4 | File metadata (`files` table: owner, title, name) | Data | Links files to owners; title field feeds the native parser |
| A5 | SQLite database (`secureshare.db`) | Data store | Holds A1 and A4 |
| A6 | Flask web application (`app/app.py`) | Process | Business logic, authN/authZ, routing |
| A7 | Native metadata parser (`native/parser*`) | Process (native code) | C binary invoked by A6 to read a file's title field |
| A8 | Export directory (`app/exports/`) | Data | Server-side file copies created by the export feature |
| A9 | `SECRET_KEY` / CSRF signing key | Secret | Signs session cookies and CSRF tokens |
| A10 | CI/CD pipeline & secrets (`.github/workflows/`) | Process / Secret | Builds, tests, and scans the application |
| A11 | Source code repository (GitHub) | Process | Git history, branches, PRs — integrity of the shipped product |

## 3. Stakeholders & Perspectives

| Stakeholder | Interest / Perspective |
|---|---|
| **End user** (file owner) | Wants their files private, available, and not alterable/removable by anyone else; wants confidence their own actions (delete, export) are the only way their data changes. |
| **Other end user** (potential attacker from inside the system) | A legitimate account holder who must be *prevented* from reaching another user's resources (A3/A4) even though they share the same application and database. |
| **Admin / operator** | Wants the service available, wants to detect and audit unauthorized-access attempts (A3/A4), wants the deployed binaries (A7) and dependencies (A10) free of known exploitable defects. |
| **External attacker** (unauthenticated or via a malicious third-party site) | Represents the threat actor in the CSRF and Clickjacking scenarios: able to get a victim's browser to send requests or render framed content, without ever having valid SecureShare credentials. |
| **Developer / DevSecOps team** | Wants a pipeline (A10) that catches regressions of the fixed vulnerabilities before merge, and a codebase where authorization is centralized (not reimplemented per-route). |

## 4. Elicited Protection Needs

Protection needs were elicited by walking each stakeholder's goals above
against each asset, and by directly targeting the five mandatory
vulnerability classes as *known failure modes to design against*.

| ID | Protection Need | Primary Asset(s) | Elicited From |
|---|---|---|---|
| PN1 | A file's content and metadata must be readable and downloadable only by its owner (or an explicitly authorized user, out of scope for this sprint). | A3, A4 | End user, other end user (IDOR) |
| PN2 | A state-changing action on a file (delete, export) must only occur as a result of a deliberate, same-origin action by the authenticated owner — never as a side-effect of visiting an unrelated site. | A3, A4 | End user (CSRF) |
| PN3 | SecureShare pages must not be embeddable in a third-party page in a way that lets an attacker trick a user into unknowingly interacting with SecureShare's real UI. | A2, A3 (indirectly, via UI redress) | End user (Clickjacking) |
| PN4 | No user-supplied value may ever be interpreted by a system shell or alter the command the server executes. | A6, A7, host OS | Admin/operator (Command Injection) |
| PN5 | No user-supplied value may be copied into a fixed-size native buffer without a bounds check; oversized input must be rejected, not silently overflow memory. | A7 | Admin/operator (Buffer Overflow) |
| PN6 | Passwords must never be stored or logged in plaintext; session identifiers must not be guessable or exposed to script/third parties. | A1, A2, A9 | End user, admin |
| PN7 | Known-vulnerable third-party dependencies must not ship in the running application. | A6 (dependencies) | Admin/operator, DevSecOps |
| PN8 | Every merge to `main` must pass automated tests and security scans; a critical/high finding must block the merge. | A10, A11 | DevSecOps |
| PN9 | Authorization logic must be centralized so a new route cannot accidentally omit an ownership check. | A6 | Developer (root-cause fix for PN1) |
| PN10 | The service should remain available to legitimate users; a single malformed request (e.g. an oversized title) must not crash the whole process. | A6, A7 | Admin/operator (Availability) |

## 5. CIA Triad Mapping

Each protection need is mapped below to the CIA properties it protects.
Mapping is explicit and intentionally many-to-many, per the CDF Unit 2 requirement.

| PN | Confidentiality | Integrity | Availability | Rationale |
|---|:---:|:---:|:---:|---|
| PN1 (IDOR fix — object-level authz) | ✅ | ✅ | — | Prevents another user from **reading** (C) and, via download/export, effectively copying/propagating (I-adjacent) another user's data. |
| PN2 (CSRF fix — anti-CSRF tokens) | — | ✅ | ✅ | A forged delete is an unauthorized **modification** (data loss); repeated forged deletes degrade availability of the user's own data. |
| PN3 (Clickjacking fix — frame-busting headers) | ✅ | ✅ | — | UI redressing can trick a user into exposing (C) or changing (I) data via clicks they did not intend. |
| PN4 (Command Injection fix — no shell) | ✅ | ✅ | ✅ | Arbitrary command execution is the most severe case: full confidentiality (read any file), integrity (modify/delete anything), and availability (crash/DoS the host) loss. |
| PN5 (Buffer Overflow fix — bounds checking) | ✅ | ✅ | ✅ | A stack overflow can crash the process (A), corrupt adjacent memory (I), and in the worst case be leveraged for code execution (C). |
| PN6 (credential/session handling) | ✅ | ✅ | — | Protects login secrecy (C) and prevents session fixation/tampering (I). |
| PN7 (dependency hygiene) | ✅ | ✅ | ✅ | A known CVE in a dependency can affect any of the three properties depending on the CVE. |
| PN8 (CI/CD security gate) | ✅ | ✅ | ✅ | Process control that prevents regressions across all three properties reaching production. |
| PN9 (centralized authorization) | ✅ | ✅ | — | Structural control that makes PN1-style confidentiality/integrity failures systematically less likely on *new* code. |
| PN10 (fail-safe input handling) | — | — | ✅ | Directly protects service availability under malformed/hostile input. |

## 6. Derived, Measurable Security Requirements

These are the testable requirements that SECURITY_IMPLEMENTATION.md and
SECURITY_TEST_REPORT.md verify against:

1. **SR-1** (← PN1, PN9): Every route that reads or mutates a `files` row MUST call
   `get_owned_file_or_403()` (or an equivalent explicit authorization check) before
   returning data; verified by `tests/test_idor.py`.
2. **SR-2** (← PN2): Every state-changing (POST) endpoint MUST reject a request
   that lacks a valid, session-bound CSRF token, with HTTP 400; verified by
   `tests/test_csrf.py`.
3. **SR-3** (← PN3): Every HTTP response MUST include `X-Frame-Options: DENY`
   and `Content-Security-Policy: frame-ancestors 'none'`; verified by
   `tests/test_clickjacking.py`.
4. **SR-4** (← PN4): No request handler may construct a shell command string
   from user input or call `subprocess`/`os.system` with `shell=True`; verified
   by `tests/test_command_injection.py` and the Bandit/Semgrep SAST gate
   (`docs/SECURITY_TEST_REPORT.md`).
5. **SR-5** (← PN5, PN10): Native code that copies a user-influenced string
   into a fixed-size buffer MUST bounds-check the input and reject (not
   truncate-and-continue) on overflow; the web layer MUST additionally
   reject an over-long title before invoking native code; verified by
   `tests/test_buffer_overflow.py` and the AddressSanitizer evidence in
   `docs/SECURITY_IMPLEMENTATION.md`.
6. **SR-6** (← PN6): Passwords MUST be stored only as salted hashes
   (`werkzeug.security.generate_password_hash`); session cookies MUST be
   `HttpOnly` and `SameSite=Lax` at minimum.
7. **SR-7** (← PN7, PN8): `pip-audit` MUST report zero known vulnerabilities
   against `requirements.txt` before merge to `main`; the CI pipeline MUST
   fail the build on a High/Critical SAST finding.

## 7. Out of Scope (Sprint Boundary)

- Explicit file-sharing-with-specific-users (grant lists) — PN1's fix uses
  strict ownership-only authorization; a sharing feature would need its own
  threat model and is left for a future iteration.
- Rate limiting / brute-force login protection — noted as a residual risk in
  `docs/THREAT_MODEL.md`, not implemented this sprint.
- TLS termination / HTTPS enforcement — assumed to be handled by a reverse
  proxy in a real deployment; `SESSION_COOKIE_SECURE` is wired to
  `FLASK_ENV=production` so it activates once TLS is in front of the app.
