/* ATA PIO driver with basic IDENTIFY and PIO read/write (LBA28).
   This is written to be readable and follow POSIX-like semantics where
   possible: functions return 0 on success and -1 on error, and public
   initialization is provided via ata_dma_init().

   Notes:
   - Only legacy IDE I/O ports are probed (primary/secondary channels).
   - Supports up to 4 devices: primary master/slave, secondary master/slave.
   - Read/write implement PIO (commands 0x20/0x30) for 512-byte sectors.
   - Error handling is conservative: operations return -1 on any failure.
*/

#include <axonos.h>
#include <disk.h>
#include <serial.h>
#include <string.h>
#include <idt.h>
#include <pic.h>
#include <devfs.h>
#include <keyboard.h>

#include "../inc/fat32.h"

#define ATA_PRIMARY_IO      0x1F0
#define ATA_PRIMARY_CTRL    0x3F6
#define ATA_SECONDARY_IO    0x170
#define ATA_SECONDARY_CTRL  0x376

#define ATA_REG_DATA(base)      (base + 0)
#define ATA_REG_ERROR(base)     (base + 1)
#define ATA_REG_SECCOUNT(base)  (base + 2)
#define ATA_REG_LBA_LOW(base)   (base + 3)
#define ATA_REG_LBA_MID(base)   (base + 4)
#define ATA_REG_LBA_HIGH(base)  (base + 5)
#define ATA_REG_DEVSEL(base)    (base + 6)
#define ATA_REG_STATUS(base)    (base + 7)
#define ATA_REG_COMMAND(base)   (base + 7)
#define ATA_REG_ALTSTATUS(ctrl) (ctrl)
#define ATA_REG_CONTROL(ctrl)   (ctrl)

/* status bits */
#define ATA_SR_BSY  0x80
#define ATA_SR_DRDY 0x40
#define ATA_SR_DF   0x20
#define ATA_SR_DRQ  0x08
#define ATA_SR_ERR  0x01

/* commands */
#define ATA_CMD_IDENTIFY    0xEC
#define ATA_CMD_READ_PIO    0x20
#define ATA_CMD_WRITE_PIO   0x30

typedef struct {
	uint16_t io_base;
	uint16_t ctrl_base;
	int is_slave; /* 0 = master, 1 = slave */
	char model[41];
	int exists;
} ata_device_t;

/* up to 4 devices indexed by registration id after registration */
static ata_device_t ata_devices[4];
static int ata_device_count = 0;

/* helper: short io delay (read altstatus 4 times) */
static void ata_io_delay(uint16_t ctrl) {
	(void)inb(ATA_REG_ALTSTATUS(ctrl));
	(void)inb(ATA_REG_ALTSTATUS(ctrl));
	(void)inb(ATA_REG_ALTSTATUS(ctrl));
	(void)inb(ATA_REG_ALTSTATUS(ctrl));
}

/* wait until BSY cleared or timeout (simple) */
static int ata_wait_ready(uint16_t io_base, uint16_t ctrl_base, int timeout_ms) {
	int loops = timeout_ms * 100; /* rough approximation */
	while (loops--) {
		/* allow user to abort long waits with Ctrl-C */
		if (keyboard_ctrlc_pending()) {
			keyboard_consume_ctrlc();
			return -1;
		}
		uint8_t status = inb(ATA_REG_STATUS(io_base));
		if (!(status & ATA_SR_BSY)) return 0;
		/* small pause */
		ata_io_delay(ctrl_base);
	}
	return -1;
}

/* Read IDENTIFY data (512 bytes) into buffer; returns 0 on success */
static int ata_identify(uint16_t io_base, uint16_t ctrl_base, int is_slave, uint16_t *out_buf) {
	/* select drive */
	outb(ATA_REG_DEVSEL(io_base), 0xA0 | (is_slave ? 0x10 : 0x00));
	/* clear registers */
	outb(ATA_REG_SECCOUNT(io_base), 0);
	outb(ATA_REG_LBA_LOW(io_base), 0);
	outb(ATA_REG_LBA_MID(io_base), 0);
	outb(ATA_REG_LBA_HIGH(io_base), 0);

	/* send IDENTIFY */
	outb(ATA_REG_COMMAND(io_base), ATA_CMD_IDENTIFY);
	/* read status */
	uint8_t status = inb(ATA_REG_STATUS(io_base));
	if (status == 0) return -1; /* no device */

	/* poll until DRQ or ERR, but protect with timeout to avoid infinite hang */
	{
		int poll = 0;
		const int POLL_MAX = 500000; /* tuned empirically */
		for (;;) {
			/* allow user to abort IDENTIFY with Ctrl-C */
			if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); return -1; }
			status = inb(ATA_REG_STATUS(io_base));
			if (status & ATA_SR_ERR) {
				kprintf("ata: identify failed (ERR) io=0x%x slave=%d\n", io_base, is_slave);
				return -1;
			}
			if (status & ATA_SR_DRQ) break;
			if (!(status & ATA_SR_BSY)) {
				/* still waiting */
			}
			if (++poll > POLL_MAX) {
				kprintf("ata: identify timeout io=0x%x slave=%d status=0x%x\n", io_base, is_slave, status);
				return -1;
			}
		}
	}

	/* read 256 words */
	insw(ATA_REG_DATA(io_base), out_buf, 256);
	return 0;
}

/* Convert model string from identify buffer (words 27..46). */
static void ata_model_from_ident(const uint16_t *ident, char *out, size_t outlen) {
	/* model is words 27..46 (20 words, 40 chars) in big-endian words */
	int pos = 0;
	for (int i = 27; i <= 46 && pos + 1 < (int)outlen; i++) {
		uint16_t w = ident[i];
		/* ATA stores strings as words with bytes swapped */
		char a = (char)(w >> 8);
		char b = (char)(w & 0xFF);
		out[pos++] = a ? a : ' ';
		if (pos < (int)outlen - 1) out[pos++] = b ? b : ' ';
	}
	out[outlen - 1] = '\0';
	/* trim trailing spaces */
	for (int i = (int)strlen(out) - 1; i >= 0; i--) {
		if (out[i] == ' ') out[i] = '\0';
		else break;
	}
}

/* PIO read of sectors (LBA28). buf must be at least sectors*512 bytes.
   Returns 0 on success. */
static int ata_pio_read(int device_id, uint32_t lba, void *buf, uint32_t sectors) {
	if (device_id < 0 || device_id >= ata_device_count) return -1;
	ata_device_t *dev = &ata_devices[device_id];
	if (!dev->exists) return -1;
	if (sectors == 0) return -1;

	while (sectors > 0) {
		uint8_t to_read = sectors > 255 ? 255 : (uint8_t)sectors;
		/* wait not busy */
		if (ata_wait_ready(dev->io_base, dev->ctrl_base, 500) != 0) return -1;

		outb(ATA_REG_SECCOUNT(dev->io_base), to_read);
		outb(ATA_REG_LBA_LOW(dev->io_base), (uint8_t)(lba & 0xFF));
		outb(ATA_REG_LBA_MID(dev->io_base), (uint8_t)((lba >> 8) & 0xFF));
		outb(ATA_REG_LBA_HIGH(dev->io_base), (uint8_t)((lba >> 16) & 0xFF));
		outb(ATA_REG_DEVSEL(dev->io_base), 0xE0 | (dev->is_slave ? 0x10 : 0x00) | ((lba >> 24) & 0x0F));
		outb(ATA_REG_COMMAND(dev->io_base), ATA_CMD_READ_PIO);

		/* for each sector */
		for (int s = 0; s < to_read; s++) {
			/* wait for DRQ */
			int pollloops = 100000;
			{
				int poll = 0;
				const int POLL_MAX = 200000;
				for (;;) {
					/* allow abort via Ctrl-C while polling */
					if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); return -1; }
					uint8_t st = inb(ATA_REG_STATUS(dev->io_base));
					if (st & ATA_SR_ERR) {
						kprintf("ata: read error dev=%d io=0x%x lba=%u\n", device_id, dev->io_base, lba);
						return -1;
					}
					if (st & ATA_SR_DRQ) break;
					if (++poll > POLL_MAX) {
						kprintf("ata: read timeout dev=%d io=0x%x lba=%u status=0x%x\n", device_id, dev->io_base, lba, st);
						return -1;
					}
				}
			}
			/* copy 256 words -> 512 bytes */
			insw(ATA_REG_DATA(dev->io_base), buf, 256);
			buf = (void *)((char *)buf + 512);
			lba++;
		}
		sectors -= to_read;
	}
	return 0;
}

/* PIO write of sectors (LBA28). */
static int ata_pio_write(int device_id, uint32_t lba, const void *buf, uint32_t sectors) {
	if (device_id < 0 || device_id >= ata_device_count) return -1;
	ata_device_t *dev = &ata_devices[device_id];
	if (!dev->exists) return -1;
	if (sectors == 0) return -1;

	while (sectors > 0) {
		uint8_t to_write = sectors > 255 ? 255 : (uint8_t)sectors;
		if (ata_wait_ready(dev->io_base, dev->ctrl_base, 500) != 0) return -1;

		outb(ATA_REG_SECCOUNT(dev->io_base), to_write);
		outb(ATA_REG_LBA_LOW(dev->io_base), (uint8_t)(lba & 0xFF));
		outb(ATA_REG_LBA_MID(dev->io_base), (uint8_t)((lba >> 8) & 0xFF));
		outb(ATA_REG_LBA_HIGH(dev->io_base), (uint8_t)((lba >> 16) & 0xFF));
		outb(ATA_REG_DEVSEL(dev->io_base), 0xE0 | (dev->is_slave ? 0x10 : 0x00) | ((lba >> 24) & 0x0F));
		outb(ATA_REG_COMMAND(dev->io_base), ATA_CMD_WRITE_PIO);

		for (int s = 0; s < to_write; s++) {
			/* wait for DRQ */
			{
				int poll = 0;
				const int POLL_MAX = 200000;
				for (;;) {
					/* allow abort via Ctrl-C while polling */
					if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); return -1; }
					uint8_t st = inb(ATA_REG_STATUS(dev->io_base));
					if (st & ATA_SR_ERR) {
						kprintf("ata: write error dev=%d io=0x%x lba=%u\n", device_id, dev->io_base, lba);
						return -1;
					}
					if (st & ATA_SR_DRQ) break;
					if (++poll > POLL_MAX) {
						kprintf("ata: write timeout dev=%d io=0x%x lba=%u status=0x%x\n", device_id, dev->io_base, lba, st);
						return -1;
					}
				}
			}
			/* write 256 words */
			outsw(ATA_REG_DATA(dev->io_base), buf, 256);
			buf = (const void *)((const char *)buf + 512);
			lba++;
		}
		sectors -= to_write;
	}
	return 0;
}

/* Register discovered device into disk layer and remember mapping */
static void ata_register_device(uint16_t io_base, uint16_t ctrl_base, int is_slave, const char *model, uint32_t sectors) {
	disk_ops_t *ops = (disk_ops_t *)kmalloc(sizeof(disk_ops_t));
	if (!ops) return;
	memset(ops, 0, sizeof(*ops));
	char namebuf[32];
	snprintf(namebuf, sizeof(namebuf), "ata_%u%s", ata_device_count, is_slave ? "s" : "m");
	ops->name = (const char *)kmalloc(strlen(namebuf) + 1);
	if (ops->name) strcpy((char *)ops->name, namebuf);
	ops->init = NULL;
	ops->read = ata_pio_read;
	ops->write = ata_pio_write;

	int id = disk_register(ops);
	if (id < 0) {
		kprintf("ata: failed to register device %s\n", namebuf);
		kfree((void *)ops->name);
		kfree(ops);
		return;
	}
	/* store mapping by registration id (id equals current ata_device_count) */
	ata_devices[id].io_base = io_base;
	ata_devices[id].ctrl_base = ctrl_base;
	ata_devices[id].is_slave = is_slave;
	ata_devices[id].exists = 1;
	strncpy(ata_devices[id].model, model, sizeof(ata_devices[id].model)-1);
	ata_devices[id].model[sizeof(ata_devices[id].model)-1] = '\0';
	ata_device_count = id + 1;
	/* concise output per user request */
	uint32_t size_mb = sectors / 2048; /* sectors * 512 / (1024*1024) */
	/* create /dev node: /dev/hdN */
	char devpath[32];
	/* create traditional /dev/hdN and Linux-style /dev/sdX */
	snprintf(devpath, sizeof(devpath), "/dev/hd%d", id);
	devfs_create_block_node(devpath, id, sectors);
	/* map 0->a,1->b... */
	char devpath2[32];
	if (id >= 0 && id < 26) {
		snprintf(devpath2, sizeof(devpath2), "/dev/sd%c", 'a' + id);
		devfs_create_block_node(devpath2, id, sectors);
	}
	/* Attempt to auto-mount FAT32 devices under /mnt (Linux-like behavior) */
	/* Probe device for FAT32 and mount at /mnt/sdX if successful */
	if (fat32_probe_and_mount(id) == 0) {
		char mntpath[32];
		if (id >= 0 && id < 26) snprintf(mntpath, sizeof(mntpath), "/mnt/sd%c", 'a' + id);
		else snprintf(mntpath, sizeof(mntpath), "/mnt/disk%d", id);
		ramfs_mkdir("/mnt");
		ramfs_mkdir(mntpath);
		struct fs_driver *drv = fat32_get_driver();
		if (drv) {
			if (fs_mount(mntpath, drv) == 0) {
				kprintf("fat32: auto-mounted device %d at %s\n", id, mntpath);
			} else {
				kprintf("fat32: auto-mount failed for device %d at %s\n", id, mntpath);
			}
		}
	}
	kprintf("ATA: found pio disk: \"%s\" model: \"%s\" size: %u MB\n", ata_devices[id].model, ata_devices[id].model, size_mb);
}

void ata_dma_init(void) {
	kprintf("ata: init start\n");
	/* register IRQ handlers for primary (14) and secondary (15) ATA IRQs
	   before probing so any interrupts generated during IDENTIFY are handled. */
	idt_set_handler(32 + 14, (void (*)(cpu_registers_t*))(&ata_io_delay)); /* placeholder to set vector now */
	/* replace with real handler below */
	idt_set_handler(32 + 14, (void (*)(cpu_registers_t*))0);
	/* set proper handler and unmask IRQs */
	extern void ata_irq_dispatch_wrapper(); /* forward declaration for casting convenience */
	idt_set_handler(32 + 14, (void (*)(cpu_registers_t*))ata_irq_dispatch_wrapper);
	pic_unmask_irq(14);
	idt_set_handler(32 + 15, (void (*)(cpu_registers_t*))ata_irq_dispatch_wrapper);
	pic_unmask_irq(15);

	/* probe standard channels */
	uint16_t bases[2] = { ATA_PRIMARY_IO, ATA_SECONDARY_IO };
	uint16_t ctrls[2] = { ATA_PRIMARY_CTRL, ATA_SECONDARY_CTRL };
	for (int ch = 0; ch < 2; ch++) {
		for (int sl = 0; sl < 2; sl++) {
			uint16_t identbuf[256];
			if (ata_identify(bases[ch], ctrls[ch], sl, identbuf) == 0) {
				char model[41] = {0};
				ata_model_from_ident(identbuf, model, sizeof(model));
				/* compute size in MB from words 60..61 (LBA28 total sectors) */
				uint32_t sectors = (uint32_t)identbuf[60] | ((uint32_t)identbuf[61] << 16);
				ata_register_device(bases[ch], ctrls[ch], sl, model, sectors);
			} else {
				/* no device or identify failed; just continue */
			}
		}
	}
	if (ata_device_count == 0) {
		kprintf("ata: no devices detected\n");
	}
	kprintf("ata: init done, devices=%d\n", ata_device_count);
}

/* IRQ handler: clear status on devices to acknowledge IRQ.
   idt_dispatch will send EOI after calling this handler. */
static void ata_irq_handler(cpu_registers_t *regs) {
	(void)regs;
	for (int i = 0; i < ata_device_count; i++) {
		if (ata_devices[i].exists) {
			/* read status to clear interrupt */
			(void)inb(ATA_REG_STATUS(ata_devices[i].io_base));
		}
	}
}

/* wrapper with C linkage used for idt_set_handler cast compatibility */
void ata_irq_dispatch_wrapper(cpu_registers_t *regs) {
	ata_irq_handler(regs);
}


