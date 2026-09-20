# HERMIAN build and packaging
#
# The eBPF object is built automatically by hermian/build.rs; nothing here
# needs to invoke the bpfel-unknown-none target directly.

.PHONY: build test lint fmt fmt-check check release deb install uninstall clean

CARGO   ?= cargo
PROFILE ?= release
VERSION := $(shell sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n1)
DIST    := dist/hermian-$(VERSION)-linux-amd64

build:
	$(CARGO) build --$(PROFILE)

test:
	$(CARGO) test

lint:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

check: fmt-check lint test

deb: build
	dpkg-buildpackage -us -uc -b

release: build
	rm -rf dist
	mkdir -p $(DIST)
	cp target/release/hermian $(DIST)/
	if [ -f target/release/libpam_hermian.so ]; then cp target/release/libpam_hermian.so $(DIST)/; fi
	cp packaging/install.sh $(DIST)/
	cp LICENSE README.md $(DIST)/
	cd dist && tar czf hermian-$(VERSION)-linux-amd64.tar.gz hermian-$(VERSION)-linux-amd64/
	@echo "release tarball: dist/hermian-$(VERSION)-linux-amd64.tar.gz"

install: build
	install -D -m 0755 target/release/hermian /usr/local/bin/hermian
	if [ -f target/release/libpam_hermian.so ]; then \
		install -D -m 0644 target/release/libpam_hermian.so /usr/lib/security/pam_hermian.so; \
	fi
	hermian enable

uninstall:
	hermian uninstall --yes

clean:
	$(CARGO) clean
	rm -rf dist
