/*
 * parser_fixed.c - "SecureShare" native metadata helper (REMEDIATED)
 * ----------------------------------------------------------------------
 * Fix for CWE-121 (Stack-based Buffer Overflow) found in native/parser.c.
 * Branch: fix/buffer-overflow
 *
 * Changes vs. the vulnerable baseline:
 *   1. strcpy() replaced with snprintf()/strncpy()-style bounded copy that
 *      can never write past sizeof(meta.title), and always NUL-terminates.
 *   2. Input length is validated BEFORE copying; oversized input is
 *      rejected with a clear error instead of being silently truncated,
 *      so truncation never masks an attack attempt.
 *   3. Built with compiler/runtime hardening enabled:
 *        -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -pie
 *      (stack canary + fortified libc string functions + ASLR/PIE).
 *   4. Recommended to additionally run under AddressSanitizer in CI/test
 *      builds: gcc -fsanitize=address -g -O1 ... (see docs/SECURITY_TEST_REPORT.md)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TITLE_MAX 64  /* sizeof(meta.title) incl. NUL terminator */

typedef struct {
    char title[TITLE_MAX];
    int  verified;
} meta_t;

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
     * writes past the destination buffer, regardless of input length. */
    int written = snprintf(out->title, TITLE_MAX, "%s", raw_title);
    if (written < 0 || (size_t)written >= TITLE_MAX) {
        fprintf(stderr, "error: title encoding failed\n");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <title-field-from-header>\n", argv[0]);
        return 1;
    }

    meta_t meta;
    if (parse_header(argv[1], &meta) != 0) {
        return 2;
    }

    printf("title=%s\n", meta.title);
    printf("verified=%d\n", meta.verified);
    return 0;
}
