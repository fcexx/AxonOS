SHELL := /bin/bash

ASM := nasm
ASM_ELF_FLAGS := -f elf64
ASM_BIN_FLAGS := -f bin
BUILD_DIR := build
ISO_DIR := iso
ISO_BOOT := $(ISO_DIR)/boot
GRUB_DIR := $(ISO_BOOT)/grub
KERNEL_SRC := kernel.asm
KERNEL_OBJ := $(BUILD_DIR)/kernel.o
KERNEL_ELF := $(BUILD_DIR)/axonos.elf
PAYLOAD_ELF := $(BUILD_DIR)/axonos.payload.elf
PAYLOAD_LZ4 := $(BUILD_DIR)/payload.lz4
PAYLOAD_BLOB_OBJ := $(BUILD_DIR)/payload_blob.o
KERNEL_BIN := $(BUILD_DIR)/kernel.bin
MULTIBOOT_SRC := multiboot.asm
MULTIBOOT_OBJ := $(BUILD_DIR)/multiboot.o
MULTIBOOT_BIN := $(BUILD_DIR)/multiboot.bin
ISO_IMAGE := $(BUILD_DIR)/axonos.iso
STUB_SRC := boot/kzip_stub.c
STUB_OBJ := $(BUILD_DIR)/$(STUB_SRC:.c=.c.o)

CC := gcc -m64
CFLAGS := -ffreestanding -nostdlib -fno-builtin -fno-stack-protector -fno-pic -mno-red-zone -mcmodel=kernel -Iinc -w -DQEMU_LOG_ENABLE

CSRCS := $(shell find . -path './build' -prune -o -path './iso' -prune -o -type f -name '*.c' -print | sed 's|^\./||')
COBJS := $(patsubst %.c,$(BUILD_DIR)/%.c.o,$(CSRCS))

ASMSRCS := $(shell find . -path './build' -prune -o -path './iso' -prune -o -type f -name '*.asm' -print | sed 's|^\./||')
ASMOBJS := $(patsubst %.asm,$(BUILD_DIR)/%.asm.o,$(ASMSRCS))

# GAS (preprocessed) assembly sources
SSRCS := $(shell find . -path './build' -prune -o -path './iso' -prune -o -type f -name '*.S' -print | sed 's|^\./||')
SOBJS := $(patsubst %.S,$(BUILD_DIR)/%.S.o,$(SSRCS))

MULTIBOOT_SRC := $(shell find . -path './build' -prune -o -path './iso' -prune -o -type f -name 'multiboot.asm' -print | sed 's|^\./||')
MULTIBOOT_OBJ := $(if $(MULTIBOOT_SRC),$(BUILD_DIR)/$(MULTIBOOT_SRC:.asm=.asm.o),)
OTHER_ASM_OBJS := $(filter-out $(MULTIBOOT_OBJ),$(ASMOBJS))
PAYLOAD_COBJS := $(filter-out $(STUB_OBJ),$(COBJS))

.PHONY: all kernel iso clean run

all: iso

kernel: $(KERNEL_BIN)

$(BUILD_DIR)/%.asm.o: %.asm
	@mkdir -p $(dir $@)
	@echo "NASM		$<"
	@$(ASM) $(ASM_ELF_FLAGS) -o $@ $<

$(BUILD_DIR)/%.c.o: %.c
	@mkdir -p $(dir $@)
	@echo "CC		$<"
	@$(CC) $(CFLAGS) -c -o $@ $<

# Build rule for GAS .S files (with C preprocessor)
$(BUILD_DIR)/%.S.o: %.S
	@mkdir -p $(dir $@)
	@echo "CC		$<"
	@$(CC) $(CFLAGS) -c -o $@ $<

$(PAYLOAD_ELF): $(OTHER_ASM_OBJS) $(SOBJS) $(PAYLOAD_COBJS)
	@mkdir -p $(BUILD_DIR)
	@echo "LD		$@"
	@ld -m elf_x86_64 -T linker.payload.ld -o $@ $^

$(PAYLOAD_LZ4): $(PAYLOAD_ELF)
	@echo "LZ4		$<"
	@lz4 -z -f --content-size "$<" "$@" >/dev/null

$(PAYLOAD_BLOB_OBJ): $(PAYLOAD_LZ4)
	@echo "LD(BIN)		$<"
	@ld -r -b binary -o "$@" "$<"

$(KERNEL_ELF): $(MULTIBOOT_OBJ) $(STUB_OBJ) $(PAYLOAD_BLOB_OBJ)
	@mkdir -p $(BUILD_DIR)
	@echo "LD		$@"
	@ld -m elf_x86_64 -T linker.stub.ld -o $@ $^

$(KERNEL_BIN): $(KERNEL_ELF)
	@objcopy -O binary $< $@

$(GRUB_DIR)/grub.cfg: | $(GRUB_DIR)
	

$(GRUB_DIR):
	@mkdir -p $(GRUB_DIR)




iso: $(KERNEL_ELF) $(GRUB_DIR)/grub.cfg
	@cp $(KERNEL_ELF) $(ISO_BOOT)/axonos.elf
	@grub-mkrescue -o $(ISO_IMAGE) $(ISO_DIR) 2>/dev/null || { \
		@echo "grub-mkrescue failed: try installing grub-pc-bin or xorriso" >&2; exit 1; \
	}

run: archive iso
	@qemu-system-x86_64 -cdrom $(ISO_IMAGE) -m 1024M -serial stdio -boot d -hda ../disk.img -device e1000,netdev=net0 -netdev user,id=net0

# Run with bridged networking (real IP from router) - requires sudo and br0 bridge
run-bridge: iso
	@echo "Note: Requires bridge 'br0' to be configured. Run with sudo."
	@qemu-system-x86_64 -cdrom $(ISO_IMAGE) -m 1024M -serial stdio -boot d -hda ../disk.img \
		-device e1000,netdev=net0 -netdev bridge,id=net0,br=br0

# Run with TAP networking (real IP from router) - requires sudo
run-tap: iso
	@echo "Creating TAP interface... (requires sudo)"
	@sudo ip tuntap add dev tap0 mode tap user $(USER) 2>/dev/null || true
	@sudo ip link set tap0 up 2>/dev/null || true
	@sudo ip link set tap0 master br0 2>/dev/null || echo "Warning: br0 not found, tap0 not bridged"
	@qemu-system-x86_64 -cdrom $(ISO_IMAGE) -m 1024M -serial stdio -boot d -hda ../disk.img \
		-device e1000,netdev=net0 -netdev tap,id=net0,ifname=tap0,script=no,downscript=no

debug: iso
	@qemu-system-x86_64 -cdrom $(ISO_IMAGE) -m 512M -serial stdio -hda ../disk.img -boot d -s -S & gdb -ex "target remote localhost:1234" $(KERNEL_ELF)

disk:
	@dd if=/dev/zero of=../disk.img bs=1M count=10
	@mkfs.fat -F 32 ../disk.img

archive:
	@if [ ! -f iso/boot/initfs.cpio ]; then \
		wget -P build apm.axont.ru/Packages/initfs.tar.xz; \
		tar -xf build/initfs.tar.xz -C iso/boot/; \
		rm build/initfs.tar.xz; \
	fi

clean:
	@rm -rf $(BUILD_DIR)
