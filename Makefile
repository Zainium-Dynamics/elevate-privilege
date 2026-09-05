# elevate-privilege — top-level build driver.
#
# The actual cross-compile logic lives in scripts/*.sh (each target here
# is a thin wrapper); this Makefile's own job is to be the one entrypoint
# and to read every path/profile value from elevate_privilege.toml via
# scripts/toml-get.py rather than duplicating any of it here — the TOML
# stays the single source of truth (same file elevate-paths reads at
# runtime), this and the crates just agree on it.

SHELL      := /bin/bash
TOML       := elevate_privilege.toml
TOML_GET   := python3 scripts/toml-get.py

PREFIX     := $(shell $(TOML_GET) paths.prefix $(TOML))
LIBDIR     := $(shell $(TOML_GET) paths.libdir $(TOML))
MODULEDIR  := $(shell $(TOML_GET) paths.module_dir $(TOML))
CONFDIR    := $(shell $(TOML_GET) paths.conf_dir $(TOML))
VERSION    := $(shell $(TOML_GET) project.version $(TOML))

.PHONY: all help host dynamic static zainium install clean distclean

all: zainium

help:
	@echo "elevate-privilege $(VERSION) — config: $(TOML)"
	@echo "  prefix=$(PREFIX)  libdir=$(LIBDIR)  module_dir=$(MODULEDIR)  conf_dir=$(CONFDIR)"
	@echo
	@echo "targets:"
	@echo "  make host      - build for this dev machine (glibc, cargo build --release)"
	@echo "  make dynamic   - cross-build the Zainium musl .so's (libelevate_pam.so.0, libpam.so.0, PAM modules)"
	@echo "  make static    - cross-build the static musl binaries (elevate, elev, vielev, elevate-umbra tools)"
	@echo "  make zainium   - dynamic + static (default)"
	@echo "  make install   - zainium, then install into a mounted Zainium root (see scripts/install.sh)"
	@echo "  make clean     - cargo clean + remove dist/"

host:
	./scripts/build-all.sh

dynamic:
	./scripts/build-zainium.sh dynamic

static:
	./scripts/build-zainium.sh static

zainium:
	./scripts/build-zainium.sh all

install: zainium
	./scripts/install.sh

clean:
	cargo clean

distclean: clean
	rm -rf dist
