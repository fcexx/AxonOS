#include <axonos.h>
#include <atapi.h>
#include <disk.h>
#include <serial.h>
#include <string.h>
#include <devfs.h>
#include <keyboard.h>
#include <heap.h>
#include <vga.h>
#include <scsi.h>

#define ATA_REG_DATA(base)      (base + 0)
#define ATA_REG_FEATURES(base)  (base + 1)
#define ATA_REG_SECCOUNT(base)  (base + 2)
#define ATA_REG_LBA_LOW(base)   (base + 3)
#define ATA_REG_LBA_MID(base)   (base + 4)
#define ATA_REG_LBA_HIGH(base)  (base + 5)
#define ATA_REG_DEVSEL(base)    (base + 6)
#define ATA_REG_STATUS(base)    (base + 7)
#define ATA_REG_COMMAND(base)   (base + 7)
#define ATA_REG_ALTSTATUS(ctrl) (ctrl)

/* status bits */
#define ATA_SR_BSY  0x80
#define ATA_SR_DRQ  0x08
#define ATA_SR_ERR  0x01

/* commands */
#define ATA_CMD_PACKET           0xA0
#define ATA_CMD_IDENTIFY_PACKET  0xA1

#define ATAPI_SECTOR_SIZE        2048
#define ATAPI_CMD_READ_12        0xA8
#define ATAPI_CMD_READ_CAPACITY  0x25

typedef struct {
	uint16_t io_base;
	uint16_t ctrl_base;
	int is_slave;
	char model[41];
	uint32_t sectors;            /* 512-byte sectors exposed via disk API */
	uint32_t atapi_block_size;   /* logical block size from READ CAPACITY */
	uint32_t atapi_block_count;  /* logical blocks from READ CAPACITY */
	int exists;
} atapi_device_t;

/* indexed by disk id from disk_register */
static atapi_device_t g_atapi_devices[DISK_MAX_DEVICES];
static int g_atapi_cd_count = 0;

static void atapi_io_delay(uint16_t ctrl) {
	(void)inb(ATA_REG_ALTSTATUS(ctrl));
	(void)inb(ATA_REG_ALTSTATUS(ctrl));
	(void)inb(ATA_REG_ALTSTATUS(ctrl));
	(void)inb(ATA_REG_ALTSTATUS(ctrl));
}

static int atapi_wait_ready(uint16_t io_base, uint16_t ctrl_base, int timeout_ms) {
	int loops = timeout_ms * 100;
	while (loops--) {
		if (keyboard_ctrlc_pending()) {
			keyboard_consume_ctrlc();
			return -1;
		}
		uint8_t status = inb(ATA_REG_STATUS(io_base));
		if (!(status & ATA_SR_BSY)) return 0;
		atapi_io_delay(ctrl_base);
	}
	return -1;
}

static int atapi_is_signature(uint8_t mid, uint8_t high) {
	/* PATAPI and SATAPI signatures */
	if (mid == 0x14 && high == 0xEB) return 1;
	if (mid == 0x69 && high == 0x96) return 1;
	return 0;
}

static int atapi_identify_packet(uint16_t io_base, uint16_t ctrl_base, int is_slave, uint16_t *out_buf) {
	outb(ATA_REG_DEVSEL(io_base), 0xA0 | (is_slave ? 0x10 : 0x00));
	atapi_io_delay(ctrl_base);

	outb(ATA_REG_SECCOUNT(io_base), 0);
	outb(ATA_REG_LBA_LOW(io_base), 0);
	outb(ATA_REG_LBA_MID(io_base), 0);
	outb(ATA_REG_LBA_HIGH(io_base), 0);

	outb(ATA_REG_COMMAND(io_base), ATA_CMD_IDENTIFY_PACKET);

	uint8_t status = 0;
	for (int i = 0; i < 2000; i++) {
		status = inb(ATA_REG_STATUS(io_base));
		if (status != 0) break;
		atapi_io_delay(ctrl_base);
	}
	if (status == 0) return -1;

	int poll = 0;
	const int POLL_MAX = 500000;
	for (;;) {
		if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); return -1; }
		status = inb(ATA_REG_STATUS(io_base));
		if (status & ATA_SR_ERR) return -1;
		if (status & ATA_SR_DRQ) break;
		if (++poll > POLL_MAX) return -1;
	}

	insw(ATA_REG_DATA(io_base), out_buf, 256);
	return 0;
}

/* Convert model string from identify buffer (words 27..46). */
static void atapi_model_from_ident(const uint16_t *ident, char *out, size_t outlen) {
	int pos = 0;
	for (int i = 27; i <= 46 && pos + 1 < (int)outlen; i++) {
		uint16_t w = ident[i];
		char a = (char)(w >> 8);
		char b = (char)(w & 0xFF);
		out[pos++] = a ? a : ' ';
		if (pos < (int)outlen - 1) out[pos++] = b ? b : ' ';
	}
	out[outlen - 1] = '\0';
	for (int i = (int)strlen(out) - 1; i >= 0; i--) {
		if (out[i] == ' ') out[i] = '\0';
		else break;
	}
}

static uint32_t atapi_be32(const uint8_t *p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Send one ATAPI PACKET command with data-in phase. */
static int atapi_packet_in(atapi_device_t *dev, const uint8_t *cdb12, void *buf, uint32_t byte_count) {
	if (!dev || !dev->exists || !cdb12) return -1;
	if (byte_count != 0 && !buf) return -1;

	if (atapi_wait_ready(dev->io_base, dev->ctrl_base, 1000) != 0) return -1;

	outb(ATA_REG_DEVSEL(dev->io_base), 0xA0 | (dev->is_slave ? 0x10 : 0x00));
	atapi_io_delay(dev->ctrl_base);
	outb(ATA_REG_FEATURES(dev->io_base), 0x00);
	outb(ATA_REG_LBA_MID(dev->io_base), (uint8_t)(byte_count & 0xFF));
	outb(ATA_REG_LBA_HIGH(dev->io_base), (uint8_t)((byte_count >> 8) & 0xFF));
	outb(ATA_REG_COMMAND(dev->io_base), ATA_CMD_PACKET);

	{
		int poll = 0;
		const int POLL_MAX = 500000;
		for (;;) {
			if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); return -1; }
			uint8_t st = inb(ATA_REG_STATUS(dev->io_base));
			if (st & ATA_SR_ERR) return -1;
			if (st & ATA_SR_DRQ) break;
			if (++poll > POLL_MAX) return -1;
		}
	}

	outsw(ATA_REG_DATA(dev->io_base), cdb12, 6);

	{
		int poll = 0;
		const int POLL_MAX = 800000;
		for (;;) {
			if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); return -1; }
			uint8_t st = inb(ATA_REG_STATUS(dev->io_base));
			if (st & ATA_SR_ERR) return -1;
			if (st & ATA_SR_DRQ) break;
			if (++poll > POLL_MAX) return -1;
		}
	}

	uint16_t dev_xfer = (uint16_t)inb(ATA_REG_LBA_MID(dev->io_base))
	                  | ((uint16_t)inb(ATA_REG_LBA_HIGH(dev->io_base)) << 8);
	uint32_t dev_bytes = dev_xfer ? (uint32_t)dev_xfer : byte_count;
	uint32_t copy_bytes = dev_bytes < byte_count ? dev_bytes : byte_count;
	uint32_t copy_words = copy_bytes / 2;

	if (copy_words) insw(ATA_REG_DATA(dev->io_base), buf, copy_words);
	if (copy_bytes & 1u) {
		uint16_t tail = 0;
		insw(ATA_REG_DATA(dev->io_base), &tail, 1);
		((uint8_t *)buf)[copy_bytes - 1] = (uint8_t)(tail & 0xFF);
	}

	if (dev_bytes > copy_bytes) {
		uint32_t drop_bytes = dev_bytes - copy_bytes;
		uint16_t sink[16];
		uint32_t drop_words = (drop_bytes + 1u) / 2u;
		while (drop_words) {
			uint32_t chunk = drop_words > 16u ? 16u : drop_words;
			insw(ATA_REG_DATA(dev->io_base), sink, chunk);
			drop_words -= chunk;
		}
	}

	if (copy_bytes < byte_count) memset((uint8_t *)buf + copy_bytes, 0, byte_count - copy_bytes);

	for (int i = 0; i < 1000; i++) {
		uint8_t st = inb(ATA_REG_STATUS(dev->io_base));
		if (!(st & ATA_SR_BSY)) break;
		atapi_io_delay(dev->ctrl_base);
	}

	return 0;
}

static int atapi_read_capacity(atapi_device_t *dev, uint32_t *out_blocks, uint32_t *out_block_size) {
	if (!dev || !out_blocks || !out_block_size) return -1;
	uint8_t cdb[12];
	uint8_t cap[8];
	memset(cdb, 0, sizeof(cdb));
	memset(cap, 0, sizeof(cap));
	cdb[0] = ATAPI_CMD_READ_CAPACITY;
	if (atapi_packet_in(dev, cdb, cap, sizeof(cap)) != 0) return -1;
	uint32_t last_lba = atapi_be32(cap + 0);
	uint32_t block_size = atapi_be32(cap + 4);
	if (block_size == 0) return -1;
	uint64_t bc = (uint64_t)last_lba + 1ULL;
	if (bc > 0xFFFFFFFFULL) bc = 0xFFFFFFFFULL;
	*out_blocks = (uint32_t)bc;
	*out_block_size = block_size;
	return 0;
}

static int atapi_read_block(atapi_device_t *dev, uint32_t atapi_lba, void *buf) {
	if (!dev || !buf || dev->atapi_block_size == 0) return -1;
	uint8_t cdb[12];
	memset(cdb, 0, sizeof(cdb));
	cdb[0] = ATAPI_CMD_READ_12;
	cdb[2] = (uint8_t)(atapi_lba >> 24);
	cdb[3] = (uint8_t)(atapi_lba >> 16);
	cdb[4] = (uint8_t)(atapi_lba >> 8);
	cdb[5] = (uint8_t)(atapi_lba);
	cdb[9] = 0x01; /* transfer length = 1 block */
	return atapi_packet_in(dev, cdb, buf, dev->atapi_block_size);
}

/* Expose ATAPI media through 512-byte sector disk API. Read-only. */
static int atapi_disk_read(int device_id, uint32_t lba, void *buf, uint32_t sectors) {
	if (device_id < 0 || device_id >= DISK_MAX_DEVICES) return -1;
	atapi_device_t *dev = &g_atapi_devices[device_id];
	if (!dev->exists) return -1;
	if (sectors == 0) return -1;
	if (dev->atapi_block_size < 512 || (dev->atapi_block_size % 512u) != 0) return -1;
	if (lba + sectors < lba) return -1;
	if (lba + sectors > dev->sectors) return -1;

	uint8_t *dst = (uint8_t *)buf;
	uint64_t start_byte = (uint64_t)lba * 512ULL;
	uint64_t remaining = (uint64_t)sectors * 512ULL;
	uint8_t *block_buf = (uint8_t *)kmalloc(dev->atapi_block_size);
	if (!block_buf) return -1;

	while (remaining > 0) {
		if (keyboard_ctrlc_pending()) {
			keyboard_consume_ctrlc();
			kfree(block_buf);
			return -1;
		}
		uint64_t blk = start_byte / dev->atapi_block_size;
		uint32_t off = (uint32_t)(start_byte % dev->atapi_block_size);
		if (blk >= dev->atapi_block_count) {
			kfree(block_buf);
			return -1;
		}
		if (atapi_read_block(dev, (uint32_t)blk, block_buf) != 0) {
			kfree(block_buf);
			return -1;
		}
		uint64_t avail = (uint64_t)dev->atapi_block_size - (uint64_t)off;
		uint64_t take = remaining < avail ? remaining : avail;
		memcpy(dst, block_buf + off, (size_t)take);
		dst += take;
		start_byte += take;
		remaining -= take;
	}

	kfree(block_buf);
	return 0;
}

static int atapi_disk_write(int device_id, uint32_t lba, const void *buf, uint32_t sectors) {
	(void)device_id;
	(void)lba;
	(void)buf;
	(void)sectors;
	return -1;
}

static int atapi_register_device(uint16_t io_base, uint16_t ctrl_base, int is_slave,
                                 const char *model, uint32_t sectors,
                                 uint32_t block_size, uint32_t block_count) {
	disk_ops_t *ops = (disk_ops_t *)kmalloc(sizeof(disk_ops_t));
	if (!ops) {
        klogprintf("ATAPI: error: failed to allocate %u bytes\n", sizeof(disk_ops_t));
        return -1;
    }
	memset(ops, 0, sizeof(*ops));

	char namebuf[32];
	snprintf(namebuf, sizeof(namebuf), "atapi_%d%s", g_atapi_cd_count, is_slave ? "s" : "m");
	ops->name = (const char *)kmalloc(strlen(namebuf) + 1);
	if (ops->name) strcpy((char *)ops->name, namebuf);
	ops->init = NULL;
	ops->read = atapi_disk_read;
	ops->write = atapi_disk_write;

	int id = disk_register(ops);
	if (id < 0 || id >= DISK_MAX_DEVICES) {
		kfree((void *)ops->name);
		kfree(ops);
        klogprintf("atapi: fatal: id < 0 or id >= DISK_MAX_DEVICES\n");
		return -1;
	}

	atapi_device_t *dev = &g_atapi_devices[id];
	memset(dev, 0, sizeof(*dev));
	dev->io_base = io_base;
	dev->ctrl_base = ctrl_base;
	dev->is_slave = is_slave;
	dev->sectors = sectors;
	dev->atapi_block_size = block_size;
	dev->atapi_block_count = block_count;
	dev->exists = 1;
	strncpy(dev->model, model, sizeof(dev->model) - 1);
	dev->model[sizeof(dev->model) - 1] = '\0';

	char path[32];
	snprintf(path, sizeof(path), "/dev/hd%d", id);
	devfs_create_block_node(path, id, sectors);
	if (id >= 0 && id < 26) {
		char letter = (char)('a' + id);
		snprintf(path, sizeof(path), "/dev/sd%c", letter);
		devfs_create_block_node(path, id, sectors);
	}

	snprintf(path, sizeof(path), "/dev/sr%d", g_atapi_cd_count);
	devfs_create_block_node(path, id, sectors);
	if (g_atapi_cd_count == 0) devfs_create_block_node("/dev/cdrom", id, sectors);
	g_atapi_cd_count++;

	uint32_t size_mb = sectors / 2048u;
	klogprintf("ATAPI: Found packet device: \"%s\" size: %u mb block=%u bytes blocks=%u\n",
	           dev->model, size_mb, block_size, block_count);
	(void)scsi_register_disk_as_lun(id, sectors, "ATAPI  ", dev->model, "1.0 ");
	return 0;
}

int atapi_try_register_device(uint16_t io_base, uint16_t ctrl_base, int is_slave) {
	outb(ATA_REG_DEVSEL(io_base), 0xA0 | (is_slave ? 0x10 : 0x00));
	atapi_io_delay(ctrl_base);
	uint8_t sig_mid = inb(ATA_REG_LBA_MID(io_base));
	uint8_t sig_high = inb(ATA_REG_LBA_HIGH(io_base));
	if (!atapi_is_signature(sig_mid, sig_high)) return -1;

	uint16_t ident[256];
	if (atapi_identify_packet(io_base, ctrl_base, is_slave, ident) != 0) return -1;

	char model[41] = {0};
	atapi_model_from_ident(ident, model, sizeof(model));

	atapi_device_t probe;
	memset(&probe, 0, sizeof(probe));
	probe.io_base = io_base;
	probe.ctrl_base = ctrl_base;
	probe.is_slave = is_slave;
	probe.exists = 1;
	probe.atapi_block_size = ATAPI_SECTOR_SIZE;

	uint32_t block_count = 0;
	uint32_t block_size = 0;
	if (atapi_read_capacity(&probe, &block_count, &block_size) != 0) return -1;
	if (block_size < 512 || (block_size % 512u) != 0) return -1;

	uint64_t sectors64 = ((uint64_t)block_count * (uint64_t)block_size) / 512ULL;
	uint32_t sectors = (sectors64 > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : (uint32_t)sectors64;
	return atapi_register_device(io_base, ctrl_base, is_slave, model, sectors, block_size, block_count);
}

void atapi_irq_ack_all(void) {
	for (int i = 0; i < DISK_MAX_DEVICES; i++) {
		if (!g_atapi_devices[i].exists) continue;
		(void)inb(ATA_REG_STATUS(g_atapi_devices[i].io_base));
	}
}
