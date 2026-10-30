# Makefile for SecureShare native metadata helper
# Lab-only: builds both the vulnerable baseline and the remediated version
# so before/after behaviour can be compared (see docs/SECURITY_IMPLEMENTATION.md).

CC = gcc

# Vulnerable baseline: mitigations deliberately disabled so the overflow
# is observable for the lab demo. NEVER build production code this way.
VULN_FLAGS = -g -O0 -fno-stack-protector -z execstack -no-pie

# Remediated build: full compiler/runtime hardening enabled.
FIXED_FLAGS = -g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE

# ASan build used in CI / fuzz-style testing to catch the overflow dynamically.
ASAN_FLAGS = -g -O1 -fsanitize=address -fno-omit-frame-pointer

all: parser parser_fixed

parser: parser.c
	$(CC) $(VULN_FLAGS) -o parser parser.c

parser_fixed: parser_fixed.c
	$(CC) $(FIXED_FLAGS) -o parser_fixed parser_fixed.c

parser_asan: parser.c
	$(CC) $(ASAN_FLAGS) -o parser_asan parser.c

parser_fixed_asan: parser_fixed.c
	$(CC) $(ASAN_FLAGS) -o parser_fixed_asan parser_fixed.c

clean:
	rm -f parser parser_fixed parser_asan parser_fixed_asan *.o

.PHONY: all clean
