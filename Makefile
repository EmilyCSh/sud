# SPDX-License-Identifier: GPL-3.0-only
#
# sud/Makefile
#
# Copyright (C) Emily <info@emy.sh>

TARGET = sud
PREFIX ?= /usr

.PHONY: all
all: check $(TARGET)


.PHONY: check
check:
	cargo fmt --check

$(TARGET):
	cargo build --release

.PHONY: install
install: target/release/$(TARGET)
	install -Dm 755 target/release/$(TARGET) $(DESTDIR)$(PREFIX)/bin/sud
	install -Dm 644 systemd/sud.socket $(DESTDIR)$(PREFIX)/lib/systemd/system/sud.socket
	install -Dm 644 /dev/null $(DESTDIR)$(PREFIX)/lib/systemd/system/sud@.service
	cat systemd/sud@.service.template | SUD_BIN=$(PREFIX)/bin/sud envsubst > $(DESTDIR)$(PREFIX)/lib/systemd/system/sud@.service

.PHONY: uninstall
uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/sud
	rm $(DESTDIR)$(PREFIX)/lib/systemd/system/sud.socket
	rm $(DESTDIR)$(PREFIX)/lib/systemd/system/sud@.service

.PHONY: test
test: target/release/$(TARGET)
	systemctl stop sud.socket || true
	install -Dm 755 target/release/$(TARGET) /tmp/sud
	install -Dm 644 systemd/sud.socket /run/systemd/transient/sud.socket
	install -Dm 644 /dev/null /run/systemd/transient/sud.service
	cat systemd/sud.service.template | SUD_BIN=/tmp/sud envsubst > /run/systemd/transient/sud.service
	systemctl daemon-reload
	systemctl start sud.socket

.PHONY: clean
clean:
	rm -rf target
