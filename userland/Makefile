# AxonOS initfs build - static busybox + axonos resolver (SYS_resolve)
# Produces initfs.cpio for kernel boot

SHELL := /bin/bash
BUILD := build
BUSYBOX_VER := 1.36.1
BUSYBOX_URL := https://busybox.net/downloads/busybox-$(BUSYBOX_VER).tar.bz2
ROOTFS := $(BUILD)/rootfs
LIBRESOLVE := libresolve
OUT_CPIO := ../iso/boot/initfs.cpio

.PHONY: all clean initfs download-busybox

download-busybox:
	@mkdir -p $(BUILD)
	@if [ ! -f $(BUILD)/busybox-$(BUSYBOX_VER).tar.bz2 ]; then \
		echo "Downloading busybox $(BUSYBOX_VER)..."; \
		wget -O $(BUILD)/busybox-$(BUSYBOX_VER).tar.bz2 $(BUSYBOX_URL) || \
		curl -L -o $(BUILD)/busybox-$(BUSYBOX_VER).tar.bz2 $(BUSYBOX_URL); \
	else echo "busybox tarball already present."; fi

all: initfs

# Build libaxonos_resolve
$(BUILD)/$(LIBRESOLVE)/libaxonos_resolve.a:
	@mkdir -p $(BUILD)/$(LIBRESOLVE)
	@cp -r $(LIBRESOLVE)/* $(BUILD)/$(LIBRESOLVE)/
	@$(MAKE) -C $(BUILD)/$(LIBRESOLVE)

# Download and extract busybox
$(BUILD)/busybox-$(BUSYBOX_VER)/.extracted:
	@mkdir -p $(BUILD)
	@if [ ! -f $(BUILD)/busybox-$(BUSYBOX_VER).tar.bz2 ]; then \
		echo "Downloading busybox $(BUSYBOX_VER)..."; \
		wget -q -O $(BUILD)/busybox-$(BUSYBOX_VER).tar.bz2 $(BUSYBOX_URL) || \
		curl -sL -o $(BUILD)/busybox-$(BUSYBOX_VER).tar.bz2 $(BUSYBOX_URL) || \
		{ echo "Error: put busybox-$(BUSYBOX_VER).tar.bz2 into userland/build/"; exit 1; }; \
	fi
	@tar -xjf $(BUILD)/busybox-$(BUSYBOX_VER).tar.bz2 -C $(BUILD)
	@touch $@

# Configure and build busybox static with axonos resolver
$(BUILD)/busybox-$(BUSYBOX_VER)/busybox: $(BUILD)/busybox-$(BUSYBOX_VER)/.extracted $(BUILD)/$(LIBRESOLVE)/libaxonos_resolve.a
	@cd $(BUILD)/busybox-$(BUSYBOX_VER) && \
		make defconfig 2>/dev/null || true
	@cd $(BUILD)/busybox-$(BUSYBOX_VER) && \
		sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config 2>/dev/null || true
	@cd $(BUILD)/busybox-$(BUSYBOX_VER) && \
		make -j$$(nproc) CFLAGS="-O2" LDFLAGS="-static -L$(abspath $(BUILD)/$(LIBRESOLVE)) -laxonos_resolve" 2>/dev/null

# Create rootfs and initfs.cpio
initfs: $(BUILD)/busybox-$(BUSYBOX_VER)/busybox
	@echo "Building initfs..."
	@rm -rf $(ROOTFS)
	@mkdir -p $(ROOTFS)/bin $(ROOTFS)/sbin $(ROOTFS)/etc $(ROOTFS)/dev $(ROOTFS)/proc $(ROOTFS)/sys
	@cp $(BUILD)/busybox-$(BUSYBOX_VER)/busybox $(ROOTFS)/bin/
	@ln -sf bin/busybox $(ROOTFS)/init
	@ln -sf busybox $(ROOTFS)/bin/sh
	@ln -sf busybox $(ROOTFS)/bin/init
	@ln -sf busybox $(ROOTFS)/bin/getty
	@ln -sf ../bin/busybox $(ROOTFS)/sbin/init
	@ln -sf busybox $(ROOTFS)/bin/ping
	@ln -sf busybox $(ROOTFS)/bin/wget
	@ln -sf busybox $(ROOTFS)/bin/mount
	@ln -sf busybox $(ROOTFS)/bin/umount
	@ln -sf busybox $(ROOTFS)/bin/ls
	@ln -sf busybox $(ROOTFS)/bin/cat
	@ln -sf busybox $(ROOTFS)/bin/echo
	@ln -sf busybox $(ROOTFS)/bin/ps
	@ln -sf busybox $(ROOTFS)/bin/kill
	@ln -sf busybox $(ROOTFS)/bin/clear
	@printf '::sysinit:/bin/mount -t proc proc /proc\n::sysinit:/bin/mount -t sysfs sysfs /sys\n::respawn:/bin/getty -L 38400 tty1\n::restart:/sbin/init\n::ctrlaltdel:/sbin/reboot\n::shutdown:/bin/umount -a -r\n' > $(ROOTFS)/etc/inittab
	@cd $(ROOTFS) && find . | cpio -o -H newc 2>/dev/null > $(abspath $(BUILD)/initfs.cpio)
	@mkdir -p $(dir $(OUT_CPIO))
	@cp $(BUILD)/initfs.cpio $(OUT_CPIO)
	@echo "initfs built: $(OUT_CPIO)"

clean:
	@rm -rf $(BUILD)
	@rm -f $(OUT_CPIO)
