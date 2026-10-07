# elevate-pam
PREFIX ?=
DESTDIR ?=

.PHONY: all release debug test modules install check-nostd fmt clippy clean version

all: release

release:
	cargo build --workspace --release

debug:
	cargo build --workspace

modules:
	./scripts/build-modules.sh release

test:
	cargo test --workspace

check-nostd:
	cargo check -p elevate-pam --no-default-features --features alloc

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# PREFIX bakes an install root into the config's [paths]; DESTDIR only stages.
install:
	PREFIX=$(PREFIX) DESTDIR=$(DESTDIR) ./scripts/install.sh

clean:
	cargo clean

version:
	cargo run -p elevate-pam-cli --release -- version
