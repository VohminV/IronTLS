NASM    = nasm
CC      = gcc
CFLAGS  ?= -O2 -Wall -Wextra
INCLUDES = -Iinclude
BUILD   = build

ASM_NAMES = it_mem sha256 hmac hkdf aes_gcm x25519 tls13
ASM_OBJS  = $(addprefix $(BUILD)/,$(addsuffix .obj,$(ASM_NAMES)))
TESTS     = test_crypto test_tls loopback
EXES      = $(addprefix $(BUILD)/,$(addsuffix .exe,$(TESTS)))

.PHONY: all test clean

all: $(EXES)

$(BUILD):
	if not exist $(BUILD) mkdir $(BUILD)

$(BUILD)/%.obj: src/%.asm include/irontls.h include/it_offsets.inc | $(BUILD)
	$(NASM) -f win64 $(INCLUDES) -o $@ $<

$(BUILD)/%.o: tests/%.c include/irontls.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD)/%.o: examples/%.c include/irontls.h | $(BUILD)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD)/%.exe: $(BUILD)/%.o $(ASM_OBJS)
	$(CC) -o $@ $< $(ASM_OBJS) -lbcrypt

test: all
	$(BUILD)/test_crypto.exe
	$(BUILD)/test_tls.exe
	$(BUILD)/loopback.exe

clean:
	if exist $(BUILD) rmdir /s /q $(BUILD)
