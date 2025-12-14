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
KERNEL_BIN := $(BUILD_DIR)/kernel.bin
MULTIBOOT_SRC := multiboot.asm
MULTIBOOT_OBJ := $(BUILD_DIR)/multiboot.o
MULTIBOOT_BIN := $(BUILD_DIR)/multiboot.bin
ISO_IMAGE := $(BUILD_DIR)/axonos.iso

CC := gcc -m64
CFLAGS := -ffreestanding -O2 -nostdlib -fno-builtin -fno-stack-protector -fno-pic -mno-red-zone -mcmodel=kernel -Iinc -w

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

.PHONY: all kernel iso clean run

all: iso

kernel: $(KERNEL_BIN)

$(BUILD_DIR)/%.asm.o: %.asm
	@mkdir -p $(dir $@)
	@$(ASM) $(ASM_ELF_FLAGS) -o $@ $<

$(BUILD_DIR)/%.c.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# Build rule for GAS .S files (with C preprocessor)
$(BUILD_DIR)/%.S.o: %.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(KERNEL_ELF): $(MULTIBOOT_OBJ) $(OTHER_ASM_OBJS) $(SOBJS) $(COBJS)
	@mkdir -p $(BUILD_DIR)
	@ld -m elf_x86_64 -T linker.ld --allow-multiple-definition -o $@ $^

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

run: iso
	@qemu-system-x86_64 -cdrom $(ISO_IMAGE) -m 512M -serial stdio -hda ../disk.img -boot d -vga cirrus

debug: iso
	@qemu-system-x86_64 -cdrom $(ISO_IMAGE) -m 512M -serial stdio -hda ../disk.img -boot d -s -S & gdb -ex "target remote localhost:1234" $(KERNEL_ELF)

disk:
	@dd if=/dev/zero of=../disk.img bs=1M count=10
	@mkfs.fat -F 32 ../disk.img

clean:
	@rm -rf $(BUILD_DIR)
