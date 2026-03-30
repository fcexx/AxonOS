#include <scsi.h>
#include <disk.h>
#include <devfs.h>
#include <string.h>
#include <klog.h>
#include <heap.h>
#include <vga.h>  /* snprintf */

#define SCSI_MAX_LUNS  8
#define SCSI_SECTOR_SIZE 512
#define SCSI_VENDOR_LEN  8
#define SCSI_PRODUCT_LEN 16
#define SCSI_REVISION_LEN 4

typedef struct scsi_lun {
	void *transport_priv;
	const scsi_transport_ops_t *ops;
	int lun_id;
	uint32_t sector_count;  /* от READ CAPACITY(10): последний LBA + 1 */
	int disk_id;            /* id из disk_register */
	int in_use;
	char vendor[SCSI_VENDOR_LEN + 1];
	char product[SCSI_PRODUCT_LEN + 1];
	char revision[SCSI_REVISION_LEN + 1];
} scsi_lun_t;

static scsi_lun_t g_luns[SCSI_MAX_LUNS];
static int g_lun_count = 0;

/* --- CDB builders (SPC-4 / SBC-3) --- */

static void cdb_test_unit_ready(uint8_t *cdb) {
	memset(cdb, 0, 6);
	cdb[0] = SCSI_TEST_UNIT_READY;
}

static void cdb_request_sense(uint8_t *cdb, size_t alloc_len) {
	memset(cdb, 0, 6);
	cdb[0] = SCSI_REQUEST_SENSE;
	cdb[4] = (uint8_t)(alloc_len > 255 ? 255 : alloc_len);
}

static void cdb_inquiry(uint8_t *cdb, size_t alloc_len) {
	memset(cdb, 0, 6);
	cdb[0] = SCSI_INQUIRY;
	cdb[4] = (uint8_t)(alloc_len > 255 ? 255 : alloc_len);
}

static void cdb_read_capacity_10(uint8_t *cdb) {
	memset(cdb, 0, 10);
	cdb[0] = SCSI_READ_CAPACITY_10;
	/* LBA=0, PMI=0 */
}

static void cdb_read_10(uint8_t *cdb, uint32_t lba, uint32_t blocks) {
	memset(cdb, 0, 10);
	cdb[0] = SCSI_READ_10;
	cdb[2] = (uint8_t)(lba >> 24);
	cdb[3] = (uint8_t)(lba >> 16);
	cdb[4] = (uint8_t)(lba >> 8);
	cdb[5] = (uint8_t)(lba);
	cdb[7] = (uint8_t)(blocks >> 8);
	cdb[8] = (uint8_t)(blocks);
}

static void cdb_write_10(uint8_t *cdb, uint32_t lba, uint32_t blocks) {
	memset(cdb, 0, 10);
	cdb[0] = SCSI_WRITE_10;
	cdb[2] = (uint8_t)(lba >> 24);
	cdb[3] = (uint8_t)(lba >> 16);
	cdb[4] = (uint8_t)(lba >> 8);
	cdb[5] = (uint8_t)(lba);
	cdb[7] = (uint8_t)(blocks >> 8);
	cdb[8] = (uint8_t)(blocks);
}

/* Парсинг READ CAPACITY(10) response: bytes 0-3 = last LBA (big-endian), 4-7 = block size. */
static int parse_read_capacity(const uint8_t *buf, uint32_t *out_last_lba, uint32_t *out_block_size) {
	if (!buf || !out_last_lba || !out_block_size) return -1;
	*out_last_lba  = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
	*out_block_size = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) | ((uint32_t)buf[6] << 8) | buf[7];
	return 0;
}

/* Копировать поле INQUIRY с обрезкой пробелов и null-terminate */
static void inquiry_str_copy(char *dst, size_t dst_size, const uint8_t *src, size_t src_len) {
	if (!dst || dst_size == 0 || !src) return;
	size_t i = 0;
	while (i < src_len && src[i] == ' ') i++;
	size_t end = src_len;
	while (end > i && src[end - 1] == ' ') end--;
	size_t cp = end - i;
	if (cp >= dst_size) cp = dst_size - 1;
	memcpy(dst, src + i, cp);
	dst[cp] = '\0';
}

static int scsi_disk_read(int device_id, uint32_t lba, void *buf, uint32_t sectors) {
	struct scsi_lun *lun = NULL;
	for (int i = 0; i < g_lun_count; i++) {
		if (g_luns[i].in_use && g_luns[i].disk_id == device_id) {
			lun = &g_luns[i];
			break;
		}
	}
	if (!lun || !lun->ops || !lun->ops->execute_command) return -1;
	if (sectors == 0) return 0;
	if (lba + sectors > lun->sector_count) return -1;

	uint8_t cdb[SCSI_CDB_MAX_LEN];
	uint32_t done = 0;
	uint8_t *p = (uint8_t *)buf;

	while (done < sectors) {
		uint32_t chunk = sectors - done;
		if (chunk > 0xFFFFu) chunk = 0xFFFFu;
		cdb_read_10(cdb, lba + done, chunk);
		size_t len = (size_t)chunk * SCSI_SECTOR_SIZE;
		int r = lun->ops->execute_command(lun->transport_priv, cdb, 10, p + (size_t)done * SCSI_SECTOR_SIZE, len, SCSI_DATA_IN);
		if (r != 0) return -1;
		done += chunk;
	}
	return 0;
}

static int scsi_disk_write(int device_id, uint32_t lba, const void *buf, uint32_t sectors) {
	struct scsi_lun *lun = NULL;
	for (int i = 0; i < g_lun_count; i++) {
		if (g_luns[i].in_use && g_luns[i].disk_id == device_id) {
			lun = &g_luns[i];
			break;
		}
	}
	if (!lun || !lun->ops || !lun->ops->execute_command) return -1;
	if (sectors == 0) return 0;
	if (lba + sectors > lun->sector_count) return -1;

	uint8_t cdb[SCSI_CDB_MAX_LEN];
	uint32_t done = 0;
	const uint8_t *p = (const uint8_t *)buf;

	while (done < sectors) {
		uint32_t chunk = sectors - done;
		if (chunk > 0xFFFFu) chunk = 0xFFFFu;
		cdb_write_10(cdb, lba + done, chunk);
		size_t len = (size_t)chunk * SCSI_SECTOR_SIZE;
		int r = lun->ops->execute_command(lun->transport_priv, cdb, 10, (void *)(p + (size_t)done * SCSI_SECTOR_SIZE), len, SCSI_DATA_OUT);
		if (r != 0) return -1;
		done += chunk;
	}
	return 0;
}

/* Публикация партиций MBR для /dev/sdX (как в ATA). */
static void scsi_publish_mbr_partitions(int device_id, char letter, uint32_t disk_sectors) {
	uint8_t mbr[512];
	if (disk_read_sectors(device_id, 0, mbr, 1) != 0) return;
	if (mbr[510] != 0x55 || mbr[511] != 0xAA) return;
	for (int i = 0; i < 4; i++) {
		const uint8_t *e = &mbr[446 + i * 16];
		uint8_t part_type = e[4];
		uint32_t start_lba = (uint32_t)e[8] | ((uint32_t)e[9] << 8) | ((uint32_t)e[10] << 16) | ((uint32_t)e[11] << 24);
		uint32_t part_sectors = (uint32_t)e[12] | ((uint32_t)e[13] << 8) | ((uint32_t)e[14] << 16) | ((uint32_t)e[15] << 24);
		if (part_type == 0 || part_sectors == 0) continue;
		if (start_lba >= disk_sectors) continue;
		if (start_lba + part_sectors < start_lba) continue;
		if (start_lba + part_sectors > disk_sectors) part_sectors = disk_sectors - start_lba;
		char ppath[32];
		snprintf(ppath, sizeof(ppath), "/dev/sd%c%d", letter, i + 1);
		devfs_create_block_node_lba(ppath, device_id, start_lba, part_sectors);
	}
}

int scsi_register_lun(void *transport_priv, const scsi_transport_ops_t *ops, int lun_id) {
	if (!ops || !ops->execute_command || g_lun_count >= SCSI_MAX_LUNS) return -1;

	int slot = -1;
	for (int i = 0; i < SCSI_MAX_LUNS; i++) {
		if (!g_luns[i].in_use) { slot = i; break; }
	}
	if (slot < 0) return -1;

	scsi_lun_t *lun = &g_luns[slot];
	memset(lun, 0, sizeof(*lun));
	lun->transport_priv = transport_priv;
	lun->ops = ops;
	lun->lun_id = lun_id;

	uint8_t cdb[SCSI_CDB_MAX_LEN];
	uint8_t cap_buf[8];

	cdb_test_unit_ready(cdb);
	if (ops->execute_command(transport_priv, cdb, 6, NULL, 0, SCSI_DATA_NONE) != 0) {
		klogprintf("scsi: lun %d TEST UNIT READY failed\n", lun_id);
		return -1;
	}

	/* INQUIRY: vendor (8), product (16), revision (4) — стандарт SPC-4
	   Читаем стандартный INQUIRY (96 байт) для полной информации */
	uint8_t inq_buf[96];
	memset(inq_buf, 0, sizeof(inq_buf));
	cdb_inquiry(cdb, sizeof(inq_buf));
	if (ops->execute_command(transport_priv, cdb, 6, inq_buf, sizeof(inq_buf), SCSI_DATA_IN) == 0) {
		inquiry_str_copy(lun->vendor, sizeof(lun->vendor), inq_buf + 8, 8);
		inquiry_str_copy(lun->product, sizeof(lun->product), inq_buf + 16, 16);
		inquiry_str_copy(lun->revision, sizeof(lun->revision), inq_buf + 32, 4);
	} else {
		lun->vendor[0] = lun->product[0] = lun->revision[0] = '\0';
	}

	cdb_read_capacity_10(cdb);
	memset(cap_buf, 0, sizeof(cap_buf));
	if (ops->execute_command(transport_priv, cdb, 10, cap_buf, sizeof(cap_buf), SCSI_DATA_IN) != 0) {
		klogprintf("scsi: lun %d READ CAPACITY failed\n", lun_id);
		return -1;
	}

	uint32_t last_lba, block_size;
	if (parse_read_capacity(cap_buf, &last_lba, &block_size) != 0) {
		klogprintf("scsi: lun %d invalid READ CAPACITY response\n", lun_id);
		return -1;
	}
	if (block_size != SCSI_SECTOR_SIZE) {
		klogprintf("scsi: lun %d block size %u unsupported, expect 512\n", lun_id, block_size);
		return -1;
	}
	/* sector_count = last_lba + 1, cap to 32-bit for disk layer */
	uint64_t sc = (uint64_t)last_lba + 1;
	lun->sector_count = sc > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)sc;

	disk_ops_t *dops = (disk_ops_t *)kmalloc(sizeof(disk_ops_t));
	if (!dops) return -1;
	memset(dops, 0, sizeof(*dops));
	char namebuf[32];
	snprintf(namebuf, sizeof(namebuf), "scsi_%d", lun_id);
	dops->name = (const char *)kmalloc(strlen(namebuf) + 1);
	if (dops->name) strcpy((char *)dops->name, namebuf);
	dops->init = NULL;
	dops->read = scsi_disk_read;
	dops->write = scsi_disk_write;

	int id = disk_register(dops);
	if (id < 0) {
		kfree((void *)dops->name);
		kfree(dops);
		return -1;
	}

	lun->disk_id = id;
	lun->in_use = 1;
	g_lun_count++;

	char devpath[32];
	snprintf(devpath, sizeof(devpath), "/dev/hd%d", id);
	devfs_create_block_node(devpath, id, lun->sector_count);

	if (id >= 0 && id < 26) {
		char letter = (char)('a' + id);
		snprintf(devpath, sizeof(devpath), "/dev/sd%c", letter);
		devfs_create_block_node(devpath, id, lun->sector_count);
		scsi_publish_mbr_partitions(id, letter, lun->sector_count);
	}

	uint32_t size_mb = lun->sector_count / 2048;
	/* Выводим полную информацию из INQUIRY: vendor (8), product (16), revision (4)
	   Используем полные данные из inq_buf для вывода без обрезания пробелов */
	char vendor_full[9] = {0}, product_full[17] = {0}, revision_full[5] = {0};
	/* Копируем без обрезки пробелов для полного вывода */
	memcpy(vendor_full, inq_buf + 8, 8);
	vendor_full[8] = '\0';
	memcpy(product_full, inq_buf + 16, 16);
	product_full[16] = '\0';
	memcpy(revision_full, inq_buf + 32, 4);
	revision_full[4] = '\0';
	/* Выводим полную информацию о диске в читаемом формате */
	klogprintf("scsi: %s disk_id=%d lun=%d\n", dops->name, id, lun_id);
	klogprintf("  vendor=\"%.8s\" model=\"%.16s\" rev=\"%.4s\"\n", vendor_full, product_full, revision_full);
	klogprintf("  sectors=%u (%u MiB) /dev/sd%c /dev/hd%d\n",
	           lun->sector_count, size_mb,
	           (id < 26) ? ('a' + id) : '?', id);

	return id;
}

/* --- API для вывода информации (например /proc/scsi/scsi) --- */
int scsi_lun_count(void) {
	return g_lun_count;
}

int scsi_lun_get_info(int index, char *vendor, size_t vlen, char *product, size_t plen,
                      char *revision, size_t rlen, uint32_t *out_sectors, int *out_disk_id, char *out_dev_letter) {
	if (index < 0 || index >= g_lun_count) return -1;
	int slot = -1;
	int n = 0;
	for (int i = 0; i < SCSI_MAX_LUNS; i++) {
		if (!g_luns[i].in_use) continue;
		if (n == index) { slot = i; break; }
		n++;
	}
	if (slot < 0) return -1;
	scsi_lun_t *lun = &g_luns[slot];
	if (vendor && vlen) { strncpy(vendor, lun->vendor, vlen - 1); vendor[vlen - 1] = '\0'; }
	if (product && plen) { strncpy(product, lun->product, plen - 1); product[plen - 1] = '\0'; }
	if (revision && rlen) { strncpy(revision, lun->revision, rlen - 1); revision[rlen - 1] = '\0'; }
	if (out_sectors) *out_sectors = lun->sector_count;
	if (out_disk_id) *out_disk_id = lun->disk_id;
	if (out_dev_letter && lun->disk_id >= 0 && lun->disk_id < 26)
		*out_dev_letter = (char)('a' + lun->disk_id);
	else if (out_dev_letter)
		*out_dev_letter = '?';
	return 0;
}

int scsi_register_disk_as_lun(int disk_id, uint32_t sectors,
                              const char *vendor, const char *product, const char *revision) {
	if (disk_id < 0 || g_lun_count >= SCSI_MAX_LUNS) return -1;
	int slot = -1;
	for (int i = 0; i < SCSI_MAX_LUNS; i++) {
		if (!g_luns[i].in_use) { slot = i; break; }
	}
	if (slot < 0) return -1;
	scsi_lun_t *lun = &g_luns[slot];
	memset(lun, 0, sizeof(*lun));
	lun->transport_priv = NULL;
	lun->ops = NULL;  /* alias: I/O через disk layer, узел /dev/sdX уже есть */
	lun->lun_id = disk_id;
	lun->sector_count = sectors;
	lun->disk_id = disk_id;
	lun->in_use = 1;
	if (vendor) { strncpy(lun->vendor, vendor, SCSI_VENDOR_LEN); lun->vendor[SCSI_VENDOR_LEN] = '\0'; }
	if (product) { strncpy(lun->product, product, SCSI_PRODUCT_LEN); lun->product[SCSI_PRODUCT_LEN] = '\0'; }
	if (revision) { strncpy(lun->revision, revision, SCSI_REVISION_LEN); lun->revision[SCSI_REVISION_LEN] = '\0'; }
	g_lun_count++;
	klogprintf("scsi: disk %d registered as SCSI LUN (vendor=%s model=%s) /dev/sd%c\n",
	           disk_id, lun->vendor, lun->product, (disk_id < 26) ? ('a' + disk_id) : '?');
	return 0;
}

void scsi_init(void) {
	memset(g_luns, 0, sizeof(g_luns));
	g_lun_count = 0;
	klogprintf("scsi: core ready (transports register LUNs via scsi_register_lun)\n");
}
