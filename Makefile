ARCH ?= aarch64

NDK_PATH    := $(HOME)/sdk/android-ndk-r27d
CLANG       := $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
TARGET_CC   := $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/$(ARCH)-linux-android35-clang
SYSROOT     := $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/sysroot

SRC_DIR     := src
OUT_DIR     := out
INC_DIR     := ./include
LIB_DIR     := ./lib/$(ARCH)


BPF_OBJ     := $(OUT_DIR)/nkbinder.bpf.o
NET_BPF_OBJ := $(OUT_DIR)/nkbinder_network.bpf.o
USER_BIN    := $(OUT_DIR)/nkbinder_$(ARCH)

BPF_CFLAGS  := -target bpf -g -O2 \
               --sysroot=$(SYSROOT) \
               -I$(SYSROOT)/usr/include \
               -I$(SYSROOT)/usr/include/$(ARCH)-linux-android \
               -I$(INC_DIR) \
               -I$(SRC_DIR)

USER_CFLAGS := -I$(INC_DIR) -I$(SRC_DIR) -O2 -Wall
USER_LDFLAGS := -L$(LIB_DIR) -l:libbpf.a -l:libelf.a -l:libzstd.a -lz -static

.PHONY: all clean prepare

all: prepare $(BPF_OBJ) $(NET_BPF_OBJ) $(USER_BIN)

prepare:
	@mkdir -p $(OUT_DIR)

$(BPF_OBJ): $(SRC_DIR)/nkbinder.bpf.c
	@echo "[+] Compiling Binder/Signal BPF program: $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(NET_BPF_OBJ): $(SRC_DIR)/nkbinder_network.bpf.c
	@echo "[+] Compiling Network BPF program (socket filter, non-CO-RE): $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): $(SRC_DIR)/nkbinder.c
	@echo "[+] Compiling User-space loader: $@"
	$(TARGET_CC) $(USER_CFLAGS) $< $(USER_LDFLAGS) -o $@

clean:
	@echo "[+] Cleaning up..."
	rm -rf $(OUT_DIR)

help:
	@echo "nkbinder build system"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build everything (default)"
	@echo "  prepare    - Create output directory"
	@echo "  clean      - Remove all build artifacts"
	@echo "  help       - Show this help"
	@echo ""
	@echo "Files generated:"
	@echo "  out/nkbinder.bpf.o           - Binder/Signal tracepoint BPF program"
	@echo "  out/nkbinder_network.bpf.o   - Network socket filter BPF program"
	@echo "  out/nkbinder_$(ARCH)          - Userspace loader"
	@echo ""
	@echo "Usage:"
	@echo "  make                    # Build all"
	@echo "  make clean              # Clean build"
	@echo "  make NET_BPF_OBJ=        # Build without network BPF"
