# Security Implementation Report
**Project:** SecureShare | **Course:** CYC386 Midterm Lab Exam
**Team:** Syed Zurriat Hussain (FA23-BCT-041), Muhammad Ahmadd (FA23-BCT-020), Junaid (FA23-BCT-057)
**Date:** 2026-10-30

For each of the five mandatory vulnerability classes: the vulnerable code,
a lab-only exploit/PoC with evidence, the fix, and verification. All
screenshots referenced below are in [`../Screenshots/`](../Screenshots/)
(sequentially numbered `01`-`12`, "FIXED" marks post-remediation evidence).
Git tags: `vulnerable-baseline` (pre-fix state) and `secure-release`
(all five fixes merged).

---

## 1. IDOR (Insecure Direct Object Reference) — CWE-639

### Vulnerable code (`vulnerable-baseline` tag, `app/app.py`)
```python
@app.route("/file/<int:file_id>")
@login_required
def view_file(file_id):
    db = get_db()
    # VULNERABLE: looks up the file by ID only - no check that the file
    # belongs to the logged-in user.
    file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    ...
```
`download_file()` had the identical pattern.

### Exploit / PoC
Setup: `alice` uploads a confidential file (becomes `file_id=1`); `bob` is a
completely unrelated, separately-registered user who owns `file_id=2`.

1. Log in as alice, confirm her file is `payroll_notes.txt` (id 1) —
   [`Screenshots/02_alice_dashboard.jpg`](../Screenshots/02_alice_dashboard.jpg).
2. Log in as bob, confirm his own dashboard only lists his own file (id 2) —
   [`Screenshots/03_bob_dashboard.jpg`](../Screenshots/03_bob_dashboard.jpg).
3. As bob, navigate directly to `GET /file/1` (alice's id, guessed by simply
   decrementing the integer). Result: full page render of alice's file,
   including her private title "Alice Q3 payroll notes" —
   [`Screenshots/04_IDOR_bob_views_alice_file.jpg`](../Screenshots/04_IDOR_bob_views_alice_file.jpg).
4. Confirmed with `curl` using bob's authenticated session cookie against
   `GET /file/1/download`:
   ```
   $ curl -s -b bob_cookies.txt http://localhost:5000/file/1/download
   CONFIDENTIAL - Alice's payroll notes
   Salary review draft: do not share.
   ```
   Full file content disclosed to an unauthorized user.

### Fix (`fix/idor` branch, commit `2f068c3`)
```python
def get_owned_file_or_403(db, file_id, user):
    file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file_row:
        abort(404)
    if file_row["owner_id"] != user["id"]:
        app.logger.warning("IDOR attempt blocked: user_id=%s tried file_id=%s "
                            "owned by user_id=%s", user["id"], file_id, file_row["owner_id"])
        abort(403)
    return file_row
```
Every file-touching route (`view_file`, `download_file`, `delete_file`,
`export_file`) now calls this single helper instead of querying `files`
directly — centralizing authorization (security requirement SR-1 /
PN9 in `docs/PNE_Report.md`) so a future new route cannot forget the check.

### Verification
- **Manual re-test:** bob → `GET /file/1` now returns **403 Forbidden** —
  [`Screenshots/09_FIXED_idor_403.jpg`](../Screenshots/09_FIXED_idor_403.jpg).
- **Automated regression:** `tests/test_idor.py` — 3 tests, all passing
  (other user blocked from view/download, owner still allowed).
- **SAST:** no change needed from Bandit/Semgrep for this class (it is a
  business-logic/authorization flaw, not pattern-matchable by generic
  static rules) — caught and fixed by manual threat modeling (Attack Tree 2,
  `docs/THREAT_MODEL.md`) and proven by the dedicated regression test instead.

---

## 2. CSRF (Cross-Site Request Forgery) — CWE-352

### Vulnerable code (`vulnerable-baseline` tag)
```python
@app.route("/file/<int:file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id):
    ...
    # VULNERABLE: relies solely on the session cookie for authorization.
    # No CSRF token is required.
    if file_row["owner_id"] == user["id"]:
        (UPLOAD_DIR / file_row["stored_name"]).unlink(missing_ok=True)
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        db.commit()
    return redirect(url_for("dashboard"))
```
No app-wide CSRF protection was configured, and the delete `<form>` had no
hidden token field.

### Exploit / PoC
1. Alice logs into SecureShare normally (a real, legitimate session).
2. While still logged in, her browser is navigated to an unrelated
   third-party page, `http://localhost:8081/win_a_prize.html` (simulating
   a phishing link / malicious ad), whose entire content is:
   ```html
   <form id="csrf-form" action="http://localhost:5000/file/1/delete" method="POST"></form>
   <script>document.getElementById('csrf-form').submit();</script>
   ```
3. The browser auto-submits the hidden form to SecureShare. Because
   browsers attach cookies to same-site requests regardless of the
   request's origin, alice's session cookie rides along and the server
   treats it as a legitimate, authenticated delete request from alice
   herself.
4. Result: alice's file is deleted **without her clicking anything on
   SecureShare**, confirmed by her dashboard immediately showing
   "No files yet." right after landing on the attacker's page —
   [`Screenshots/05_CSRF_file_autodeleted.jpg`](../Screenshots/05_CSRF_file_autodeleted.jpg).

### Fix (`fix/csrf` branch, commit `5711e12`)
```python
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
csrf = CSRFProtect(app)
```
plus a hidden `{{ csrf_token() }}` field added to every POST `<form>`
(login, register, upload, delete, export). Flask-WTF validates the
synchronizer token on every state-changing request and rejects a missing
or invalid one with HTTP 400.

### Verification
- **Manual re-test:** the exact same attacker page is revisited — result
  is now **"400 Bad Request: The CSRF token is missing."** and the
  targeted file is confirmed untouched —
  [`Screenshots/11_FIXED_csrf_blocked.jpg`](../Screenshots/11_FIXED_csrf_blocked.jpg).
- **Automated regression:** `tests/test_csrf.py` — 2 tests: a forged
  request (no token) is rejected (400), and a legitimate request (token
  read from the real rendered form, as a browser would) still succeeds.

---

## 3. Clickjacking — CWE-1021

### Vulnerable code (`vulnerable-baseline` tag)
No `after_request` handler existed at all — every response was sent with
no `X-Frame-Options` or `Content-Security-Policy` header.

### Exploit / PoC
An attacker page overlays a mostly-transparent `<iframe src="http://localhost:5000/">`
on top of a decoy "Win a free gift card" UI, so a victim's click on the
decoy actually lands on SecureShare's real, hidden button underneath
(classic UI redressing):
```html
<iframe src="http://localhost:5000/" style="opacity:0.25; position:absolute; ..."></iframe>
```
Loading this page renders the full, interactive SecureShare dashboard
inside the attacker's frame with no refusal from the browser —
[`Screenshots/06_clickjacking_framed.jpg`](../Screenshots/06_clickjacking_framed.jpg).
Combined with CSRF (§2), this could be used to disguise a forged action as
an innocuous click (e.g. "claim your prize").

### Fix (`fix/clickjacking` branch, commit `ef97471`)
```python
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response
```
Both headers are sent together: `X-Frame-Options` for broad/legacy browser
coverage, `frame-ancestors 'none'` (CSP) as the modern standard — satisfying
the assignment's "X-Frame-Options and/or CSP frame-ancestors" requirement
with both for defense-in-depth.

### Verification
- **Manual re-test:** the identical attacker page now renders an **empty
  iframe** — the browser refuses to display SecureShare inside the frame —
  [`Screenshots/10_FIXED_clickjacking_blocked.jpg`](../Screenshots/10_FIXED_clickjacking_blocked.jpg).
- **Header check:**
  ```
  $ curl -sI http://localhost:5000/login | grep -iE "x-frame|content-security"
  X-Frame-Options: DENY
  Content-Security-Policy: frame-ancestors 'none'
  ```
- **Automated regression:** `tests/test_clickjacking.py` — 2 tests confirm
  both headers are present on an unauthenticated page (`/login`) and an
  authenticated one (`/`).

---

## 4. Command Injection — CWE-78

### Vulnerable code (`vulnerable-baseline` tag)
```python
@app.route("/file/<int:file_id>/export", methods=["POST"])
@login_required
def export_file(file_id):
    ...
    export_name = request.form.get("export_name", "export")
    src = UPLOAD_DIR / file_row["stored_name"]
    dst_pattern = EXPORT_DIR / f"{export_name}"
    # VULNERABLE: shell=True with user-controlled export_name.
    cmd = f"cp '{src}' '{dst_pattern}'"
    subprocess.run(cmd, shell=True)
```

### Exploit / PoC
The single-quoted `export_name` can be broken out of by including a `'`
in the payload itself:
```
export_name = x'; id > /tmp/cmdi_proof.txt; echo pwned > /tmp/cmdi_marker.txt; echo '
```
which turns the executed shell command into:
```bash
cp '<src>' 'x'; id > /tmp/cmdi_proof.txt; echo pwned > /tmp/cmdi_marker.txt; echo ''
```
— three separate shell commands, the middle two entirely attacker-chosen.
Submitted as bob (an ordinary authenticated user exporting his *own*
file — no special privilege needed):
```
$ curl -s -b bob_cookies.txt -X POST http://localhost:5000/file/2/export \
    --data-urlencode "export_name=x'; id > /tmp/cmdi_proof.txt; echo pwned > /tmp/cmdi_marker.txt; echo '" \
    -o /dev/null -w "HTTP %{http_code}\n"
HTTP 302
$ cat /tmp/cmdi_proof.txt
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),... (full groups list)
$ cat /tmp/cmdi_marker.txt
pwned
```
The injected `id` command ran with the web server process's own OS
privileges and wrote arbitrary files to `/tmp`, completely outside the
intended export directory — full evidence rendered in
[`Screenshots/07_command_injection_proof.jpg`](../Screenshots/07_command_injection_proof.jpg).
This is the Critical (CVSS 9.9) finding — see `docs/THREAT_MODEL.md` §5.

### Fix (`fix/command-injection` branch, commit `fab7c8a`)
```python
SAFE_EXPORT_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

@app.route("/file/<int:file_id>/export", methods=["POST"])
@login_required
def export_file(file_id):
    ...
    export_name = request.form.get("export_name", "export")
    if not SAFE_EXPORT_NAME.match(export_name):
        flash("Invalid export name: use only letters, numbers, '.', '-', '_'.")
        return redirect(url_for("view_file", file_id=file_id))
    src = UPLOAD_DIR / file_row["stored_name"]
    dst = EXPORT_DIR / export_name
    # FIX: no shell at all - shutil.copyfile() calls the OS copy
    # primitives directly.
    shutil.copyfile(src, dst)
```
Two independent layers: (1) **no shell is invoked** — `shutil.copyfile()`
removes the entire class of shell-metacharacter injection, not just this
specific payload; (2) a strict allow-list on `export_name` as
defense-in-depth (also closes a latent path-traversal angle).

### Verification
- **Manual re-test (UI):** the identical payload typed into the Export
  field is now rejected client-visibly with **"Invalid export name: use
  only letters, numbers, '.', '-', '_'."** and no proof file is created —
  [`Screenshots/12_FIXED_command_injection_blocked.jpg`](../Screenshots/12_FIXED_command_injection_blocked.jpg).
- **Automated regression:** `tests/test_command_injection.py` — reproduces
  the exact original payload and asserts the marker file is never created,
  plus confirms a legitimate export name (`report-v1.txt`) still works.
- **SAST:** Bandit's `B602` (High: `subprocess_popen_with_shell_equals_true`)
  finding is **gone** post-fix (see `docs/SECURITY_TEST_REPORT.md`).

---

## 5. Buffer Overflow — CWE-121 (Stack-based Buffer Overflow)

### Vulnerable code (`native/parser.c`, `vulnerable-baseline` tag — file
kept permanently at this path as the documented "before" artifact; see
`native/parser_fixed.c` for the "after")
```c
typedef struct {
    char title[64];   /* fixed-size stack buffer - the overflow target */
    int  verified;
} meta_t;

static void parse_header(const char *raw_title) {
    meta_t meta;
    meta.verified = 0;
    /* VULNERABLE: no length check against sizeof(meta.title). */
    strcpy(meta.title, raw_title);
    ...
}
```
Built deliberately without mitigations for the lab demo:
`gcc -g -O0 -fno-stack-protector -z execstack -no-pie`.
The app invokes this binary (via `subprocess`, argv array, no shell — see
the SAST-triage note in `app/app.py`) on the file's `title` field whenever
`/file/<id>` is viewed.

### Exploit / PoC
A title longer than 63 bytes overflows the 64-byte `title` buffer:
```
$ ./parser "Q3 Budget Notes"
title=Q3 Budget Notes
verified=0
exit=0

$ ./parser "$(python3 -c 'print("A"*100)')"
Segmentation fault
exit=139   # 128 + SIGSEGV
```
AddressSanitizer confirms the exact defect, down to the line number:
```
==42286==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 101 at ... thread T0
    #1 in parse_header native/parser.c:48    <- strcpy(meta.title, raw_title)
    #2 in main native/parser.c:59
This frame has 1 object(s): [48, 116) 'meta'  <== overflows this variable
```
Full terminal evidence captured in
[`Screenshots/08_buffer_overflow_before_after.jpg`](../Screenshots/08_buffer_overflow_before_after.jpg).
This is a High (CVSS 7.1) finding — see `docs/THREAT_MODEL.md` §5; a
reliable, attacker-triggerable crash (Denial of Service) of the native
helper process on every over-long title, with the overflow also
confirmed to reach adjacent stack data (the `verified` field).

### Fix (`native/parser_fixed.c`, wired in via `fix/buffer-overflow`
branch, commit `c6afce7`)
```c
#define TITLE_MAX 64

static int parse_header(const char *raw_title, meta_t *out) {
    size_t len = strlen(raw_title);
    /* FIX: explicit bounds check, reject rather than silently truncate. */
    if (len >= TITLE_MAX) {
        fprintf(stderr, "error: title field too long (%zu bytes, max %d)\n",
                len, TITLE_MAX - 1);
        return -1;
    }
    out->verified = 0;
    /* FIX: bounded copy; snprintf guarantees NUL-termination and never
     * writes past the destination buffer. */
    int written = snprintf(out->title, TITLE_MAX, "%s", raw_title);
    ...
}
```
Built **with** compiler/runtime hardening enabled (per CDF §6.5):
```
gcc -g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE \
    -o parser_fixed parser_fixed.c
```
(`-fstack-protector-strong` = stack canary, `-D_FORTIFY_SOURCE=2` =
fortified libc string functions as a second line of defense even if a
future bug reintroduces an unsafe call, `-pie` = ASLR-compatible position-
independent executable). `app/app.py`'s `NATIVE_PARSER` now points at
`parser_fixed`, and a matching `TITLE_MAX_LEN` check was added at `/upload`
time so an over-long title is rejected at the web layer before native code
is ever invoked (defense-in-depth per security requirement SR-5).

### Verification
- **Manual re-test:** identical 100-byte input against `parser_fixed`:
  ```
  $ ./parser_fixed "$(python3 -c 'print("A"*100)')"
  error: title field too long (100 bytes, max 63)
  exit=2        # rejected safely, no crash, no overflow
  $ ./parser_fixed "Q3 Budget Notes"
  title=Q3 Budget Notes
  verified=0
  exit=0        # normal input still works correctly
  ```
  See the right half of
  [`Screenshots/08_buffer_overflow_before_after.jpg`](../Screenshots/08_buffer_overflow_before_after.jpg).
- **AddressSanitizer re-run against `parser_fixed_asan`:** no overflow
  report — clean exit.
- **Automated regression:** `tests/test_buffer_overflow.py` — an over-long
  title is rejected at `/upload` before it can reach native code; a
  simulated legacy over-long row (bypassing the web check) is still
  handled safely by `parser_fixed` without a 500/crash.

---

## 6. Compiler / Runtime Defense Summary (CDF §6.5)

| Build | Flags | Purpose |
|---|---|---|
| `native/parser` (vulnerable, intentionally) | `-fno-stack-protector -z execstack -no-pie` | Mitigations deliberately **disabled** so the overflow is directly observable for the lab demo. **Never** build production code this way. |
| `native/parser_fixed` (production) | `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE` | Stack canary detects/aborts on stack corruption; fortified libc catches unsafe string-function misuse at compile/runtime; PIE enables ASLR for the process image. |
| `native/parser_asan`, `native/parser_fixed_asan` | `-fsanitize=address -fno-omit-frame-pointer` | AddressSanitizer instrumentation used only for testing/CI (`docs/SECURITY_TEST_REPORT.md`), not shipped to production. |

All three build targets are defined in [`native/Makefile`](../native/Makefile).
