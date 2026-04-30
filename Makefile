# SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
#
# Copy Fail -- CVE-2026-31431
# AF_ALG + splice() page-cache-mutation LPE proof-of-concept.
# Disclosed 2026-04-29 by Theori / Xint. Writeup: https://copy.fail/
#
# Build flow:
#   payload.c -> payload         ($(CC), nolibc, freestanding, static)
#   payload   -> payload.o       ($(LD) -r -b binary, raw bytes -> .o)
#   exploit.c + payload.o -> exploit
#
# `ld -r -b binary` synthesizes three symbols in payload.o, mangling the
# input filename: _binary_payload_start, _binary_payload_end, _binary_payload_size.
# exploit.c declares the first two as extern and gets the bytes for free
# at link time.
#
# Toolchain knobs:
#   CC     compiler for both    (default: cc)
#   LD     linker for embed     (default: ld)
#
# For cross-compilation, point both at the cross toolchain:
#     make CC=aarch64-linux-gnu-gcc LD=aarch64-linux-gnu-ld
#
# nolibc.h handles per-arch syscall asm internally. Supported arches:
# x86_64, i386, arm, aarch64, riscv32/64, mips, ppc, s390x, loongarch,
# m68k, sh, sparc.

CC ?= cc
LD ?= ld

CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?= -Wl,-z,noexecstack

# nolibc / freestanding payload build:
#   -nostdlib                       no glibc/musl init or libs
#   -static                         no dynamic linker
#   -ffreestanding                  no hosted-environment assumptions
#   -fno-asynchronous-unwind-tables drop .eh_frame
#   -fno-ident                      drop .comment section
#   -fno-stack-protector            we have no __stack_chk_fail
#   -Os -s                          size-opt + strip
#   -Inolibc                        find nolibc.h
#
# Linker flags:
#   -Wl,-N                          merge text+data into one RWX LOAD segment
#                                   (saves ~10 KB of page-alignment padding;
#                                   produces a "RWX permissions" warning that
#                                   is informational only, not a runtime issue)
#   -Wl,-z,max-page-size=0x10       tell ld page alignment is 16 bytes -- pure
#                                   on-disk packing, kernel still uses 4 KB
#                                   pages at runtime
PAYLOAD_CFLAGS ?= -nostdlib -static -Os -s \
                  -ffreestanding \
                  -fno-asynchronous-unwind-tables \
                  -fno-ident \
                  -fno-stack-protector \
                  -Inolibc \
                  -Wl,-N \
                  -Wl,-z,max-page-size=0x10

.PHONY: all clean info musl-static

all: exploit

# musl-static: tiny (~55 KB exploit + ~1.5 KB payload), no glibc dependency.
# Requires musl-tools and linux-libc-dev. musl-gcc isolates its include path
# and doesn't expose kernel UAPI headers, so we shim them via symlink.
ARCH := $(shell uname -m)
musl-static:
	@mkdir -p .musl-shim
	@ln -sfn /usr/include/linux        .musl-shim/linux
	@ln -sfn /usr/include/asm-generic  .musl-shim/asm-generic
	@ln -sfn /usr/include/$(ARCH)-linux-gnu/asm .musl-shim/asm
	$(MAKE) CC=musl-gcc \
	    PAYLOAD_CFLAGS="$(PAYLOAD_CFLAGS) -isystem $(CURDIR)/.musl-shim" \
	    CFLAGS="$(CFLAGS) -isystem $(CURDIR)/.musl-shim"

payload: payload.c
	$(CC) $(PAYLOAD_CFLAGS) $< -o $@

# Note: the synthesized symbol names are derived from the input filename as
# given on the command line. We pass `payload` (not `./payload`), so the
# symbols are _binary_payload_start etc., not _binary___payload_start.
payload.o: payload
	$(LD) -r -b binary -o $@ $<

exploit: exploit.c payload.o
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $@ $^

info: payload payload.o
	@echo "=== payload size ==="
	@stat -c '%n: %s bytes' payload
	@SZ=$$(stat -c '%s' payload); echo "  -> $$(( (SZ + 3) / 4 )) patch_chunk iterations"
	@echo
	@echo "=== payload.o symbols ==="
	@nm payload.o
	@echo
	@echo "=== payload sections ==="
	@readelf -S payload | grep -E 'Name|\.text|\.rodata|\.data|\.bss' | head -10

clean:
	rm -rf exploit payload payload.o .musl-shim
