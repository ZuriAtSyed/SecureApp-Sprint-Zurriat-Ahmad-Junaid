/*
 * parser.c - "SecureShare" native metadata helper (VULNERABLE BASELINE)
 * ----------------------------------------------------------------------
 * Lab-only artifact for CYC386 Midterm Sprint - Buffer Overflow demo.
 *
 * Purpose: parses a tiny custom file-metadata header that the SecureShare
 * web app writes next to every upload (app/app.py: save_metadata_header()).
 * The header format is:
 *
 *      "SSMETA1:<title-string>\n"
 *
 * This native helper is invoked by the Flask app (via subprocess) whenever
 * a user views a file's details, so it can show the embedded "title"
 * field pulled from the file's own metadata header.
 *
 * THIS VERSION IS INTENTIONALLY VULNERABLE (CWE-121: Stack-based Buffer
 * Overflow). It copies the attacker-controlled title field into a
 * fixed-size 64-byte stack buffer with strcpy(), performing no bounds
 * check. A title longer than 63 bytes overflows the buffer and can
 * corrupt the saved return address / adjacent stack data, as demonstrated
 * in docs/SECURITY_IMPLEMENTATION.md.
 *
 * Build (deliberately WITHOUT modern mitigations so the overflow is
 * observable under ASAN / gdb for the lab demo):
 *      gcc -g -O0 -fno-stack-protector -z execstack -no-pie \
 *          -o native/parser native/parser.c
 *
 * DO NOT deploy this binary. See native/parser_fixed.c for the
 * remediated version used in production (fix/buffer-overflow branch).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char title[64];   /* fixed-size stack buffer - the overflow target */
    int  verified;     /* adjacent stack data that can be corrupted    */
} meta_t;

static void parse_header(const char *raw_title) {
    meta_t meta;
    meta.verified = 0;

    /* VULNERABLE: no length check against sizeof(meta.title).
     * An attacker-supplied title longer than 63 bytes overflows
     * `title` and can overwrite `verified` and/or the saved
     * return address further up the stack. */
    strcpy(meta.title, raw_title);

    printf("title=%s\n", meta.title);
    printf("verified=%d\n", meta.verified);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <title-field-from-header>\n", argv[0]);
        return 1;
    }
    parse_header(argv[1]);
    return 0;
}
