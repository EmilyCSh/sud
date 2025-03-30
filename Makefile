# SPDX-License-Identifier: GPL-3.0-only
#
# sud/Makefile
#
# Copyright (C) Emily <info@emy.sh>

TARGET = sud
CC ?= gcc
INCLUDE_DIR = $(CURDIR)/include
BUILD_DIR ?= .build
OBJ_DIR ?= $(BUILD_DIR)/obj

CFLAGS = -I$(INCLUDE_DIR) -std=gnu23 -D_GNU_SOURCE -Wall -Wextra -Werror -Werror=vla -O2 -fhardened
LFLAGS = -lcrypt -lsystemd -lpam -Wl,--fatal-warnings -Wl,--warn-common -Wl,--gc-sections -Wl,-z,now
CLANG_FORMAT_FLAGS =  --Werror --dry-run --ferror-limit=5

PREFIX ?= /usr

SOURCES = $(wildcard src/*.c)
HEADERS = $(wildcard $(INCLUDE_DIR)/sud/*.h)

OBJCC=${patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(SOURCES))}

.PHONY: all
all: check $(SOURCES) $(TARGET)

$(OBJ_DIR)/:
	mkdir -p $@

$(OBJ_DIR)/%.o: src/%.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ_DIR)/ $(OBJCC)
	$(CC) $(LFLAGS) $(OBJCC) -o $(TARGET)

$(BUILD_DIR)/sud@.service: $(BUILD_DIR)/sud@.service.template
	export SUD_BIN=
	cat $@ | envsubst > $<

.PHONY: check
check:
	clang-format $(CLANG_FORMAT_FLAGS) $(HEADERS) $(SOURCES)

.PHONY: install
install: $(TARGET)
	install -Dm 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/sud
	install -Dm 644 systemd/sud.socket $(DESTDIR)$(PREFIX)/lib/systemd/system/sud.socket
	install -Dm 644 /dev/null $(DESTDIR)$(PREFIX)/lib/systemd/system/sud@.service
	cat systemd/sud@.service.template | SUD_BIN=$(PREFIX)/bin/sud envsubst > $(DESTDIR)$(PREFIX)/lib/systemd/system/sud@.service

.PHONY: uninstall
uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/sud
	rm $(DESTDIR)$(PREFIX)/lib/systemd/system/sud.socket
	rm $(DESTDIR)$(PREFIX)/lib/systemd/system/sud@.service

.PHONY: test
test: $(TARGET)
	systemctl stop sud.socket || true
	install -Dm 755 $(TARGET) /tmp/sud
	install -Dm 644 systemd/sud.socket /run/systemd/transient/sud.socket
	install -Dm 644 /dev/null /run/systemd/transient/sud@.service
	cat systemd/sud@.service.template | SUD_BIN=/tmp/sud envsubst > /run/systemd/transient/sud@.service
	systemctl daemon-reload
	systemctl start sud.socket

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)
	rm -f $(TARGET)
