NDK_PATH    := $(HOME)/sdk/android-ndk-r27d
CLANG       := $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
TARGET_CC   := $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
SYSROOT     := $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/sysroot

SRC_DIR     := src
OUT_DIR     := out
INC_DIR     := ./include
LIB_DIR     := ./lib

BPF_OBJ     := $(OUT_DIR)/nkbinder.bpf.o
USER_BIN    := $(OUT_DIR)/nkbinder

BPF_CFLAGS  := -target bpf -g -O2 \
               --sysroot=$(SYSROOT) \
               -I$(SYSROOT)/usr/include \
               -I$(SYSROOT)/usr/include/aarch64-linux-android \
               -I$(INC_DIR) \
               -I$(SRC_DIR)

USER_CFLAGS := -I$(INC_DIR) -I$(SRC_DIR) -O2 -Wall
USER_LDFLAGS := -L$(LIB_DIR) -l:libbpf.a -l:libelf.a -l:libzstd.a -lz -static

.PHONY: all clean prepare

all: prepare $(BPF_OBJ) $(USER_BIN)

prepare:
	@mkdir -p $(OUT_DIR)

$(BPF_OBJ): $(SRC_DIR)/nkbinder.bpf.c
	@echo "[+] Compiling BPF program: $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): $(SRC_DIR)/nkbinder.c
	@echo "[+] Compiling User-space loader: $@"
	$(TARGET_CC) $(USER_CFLAGS) $< $(USER_LDFLAGS) -o $@

clean:
	@echo "[+] Cleaning up..."
	rm -rf $(OUT_DIR)