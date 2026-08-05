.PHONY: all release test modules install clean check-nostd

all: release

release:
	cargo build -p elevate-pam -p elevate-pam-cli --release

test:
	cargo test -p elevate-pam

modules:
	./scripts/build-modules.sh release

install:
	./scripts/install-dev.sh

check-nostd:
	cargo check -p elevate-pam --no-default-features --features alloc

clean:
	cargo clean

version:
	cargo run -p elevate-pam-cli --release -- version
