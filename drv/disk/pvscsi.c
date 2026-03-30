/*
 * VMware PVSCSI — минимальный драйвер для виртуального SCSI-диска в VMware (Hard Disk (SCSI)).
 * PCI: VMware 15AD:07C0. Регистрирует LUN 0:0 через scsi_register_lun() -> /dev/sdX.
 */
#include <axonos.h>
#include <pci.h>
#include <mmio.h>
#include <disk.h>
#include <devfs.h>
#include <scsi.h>
#include <string.h>
#include <klog.h>
#include <heap.h>
#include <paging.h>
#include <serial.h>
#include <pit.h>

#define PVSCSI_VENDOR_ID  0x15AD
#define PVSCSI_DEVICE_ID  0x07C0
#define PVSCSI_PAGE_SIZE  4096

/* Register offsets (vmw_pvscsi.h) */
#define PVSCSI_REG_COMMAND        0x0
#define PVSCSI_REG_COMMAND_DATA   0x4
#define PVSCSI_REG_COMMAND_STATUS 0x8
#define PVSCSI_REG_KICK_NON_RW_IO 0x3014
#define PVSCSI_REG_KICK_RW_IO     0x4018

#define PVSCSI_CMD_ADAPTER_RESET  1
#define PVSCSI_CMD_SETUP_RINGS    3
#define PVSCSI_CMD_ISSUE_SCSI     2

#define PVSCSI_FLAG_CMD_DIR_NONE     (1u << 2)
#define PVSCSI_FLAG_CMD_DIR_TOHOST   (1u << 3)
#define PVSCSI_FLAG_CMD_DIR_TODEVICE (1u << 4)

#define PVSCSI_MAX_REQ_ENTRIES_PER_PAGE  (PVSCSI_PAGE_SIZE / 128)
#define PVSCSI_MAX_CMP_ENTRIES_PER_PAGE  (PVSCSI_PAGE_SIZE / 32)
#define PVSCSI_SETUP_RINGS_MAX_NUM_PAGES 32

typedef struct pvscsi_rings_state {
	uint32_t reqProdIdx;
	uint32_t reqConsIdx;
	uint32_t reqNumEntriesLog2;
	uint32_t cmpProdIdx;
	uint32_t cmpConsIdx;
	uint32_t cmpNumEntriesLog2;
	uint32_t reqCallThreshold;
	uint8_t  _pad[100];
	uint32_t msgProdIdx;
	uint32_t msgConsIdx;
	uint32_t msgNumEntriesLog2;
} __attribute__((packed)) pvscsi_rings_state_t;

typedef struct pvscsi_req_desc {
	uint64_t context;
	uint64_t dataAddr;
	uint64_t dataLen;
	uint64_t senseAddr;
	uint32_t senseLen;
	uint32_t flags;
	uint8_t  cdb[16];
	uint8_t  cdbLen;
	uint8_t  lun[8];
	uint8_t  tag;
	uint8_t  bus;
	uint8_t  target;
	uint16_t vcpuHint;
	uint8_t  unused[58];
} __attribute__((packed)) pvscsi_req_desc_t;

typedef struct pvscsi_cmp_desc {
	uint64_t context;
	uint64_t dataLen;
	uint32_t senseLen;
	uint16_t hostStatus;
	uint16_t scsiStatus;
	uint32_t _pad[2];
} __attribute__((packed)) pvscsi_cmp_desc_t;

typedef struct pvscsi_setup_rings_cmd {
	uint32_t reqRingNumPages;
	uint32_t cmpRingNumPages;
	uint64_t ringsStatePPN;
	uint64_t reqRingPPNs[PVSCSI_SETUP_RINGS_MAX_NUM_PAGES];
	uint64_t cmpRingPPNs[PVSCSI_SETUP_RINGS_MAX_NUM_PAGES];
} __attribute__((packed)) pvscsi_setup_rings_cmd_t;

#define BTSTAT_SUCCESS  0x00
#define BTSTAT_SELTIMEO 0x11

static void *g_pvscsi_mmio;       /* NULL если используем I/O порты */
static uint16_t g_pvscsi_io_base; /* базовый порт при I/O BAR */
static int g_pvscsi_use_io;       /* 1 = регистры через I/O порты */
static pvscsi_rings_state_t *g_rings_state;
static pvscsi_req_desc_t    *g_req_ring;
static pvscsi_cmp_desc_t    *g_cmp_ring;
static uint32_t g_req_mask;
static uint32_t g_cmp_mask;
static int g_pvscsi_ready;

extern uint64_t virt_to_phys(uint64_t va);

/* Выделяет size байт с выравниванием align; в *out_raw записывает указатель для kfree. */
static void *pvscsi_alloc_aligned(size_t size, size_t align, void **out_raw) {
	void *raw = kmalloc(size + align);
	if (!raw) return NULL;
	*out_raw = raw;
	uintptr_t aligned = ((uintptr_t)raw + align - 1) & ~(align - 1);
	return (void *)aligned;
}

static void pvscsi_write32(uint32_t offset, uint32_t val) {
	if (g_pvscsi_use_io)
		outportl(g_pvscsi_io_base + (uint16_t)offset, val);
	else
		mmio_write32(g_pvscsi_mmio, offset, val);
}

static uint32_t pvscsi_read32(uint32_t offset) {
	if (g_pvscsi_use_io)
		return inportl(g_pvscsi_io_base + (uint16_t)offset);
	return mmio_read32(g_pvscsi_mmio, offset);
}

static void pvscsi_write_cmd(uint32_t cmd, const void *desc, size_t len_dwords) {
	pvscsi_write32(PVSCSI_REG_COMMAND, cmd);
	if (desc && len_dwords) {
		const uint32_t *p = (const uint32_t *)desc;
		for (size_t i = 0; i < len_dwords; i++)
			pvscsi_write32(PVSCSI_REG_COMMAND_DATA, p[i]);
	}
}

static uint32_t pvscsi_read_status(void) {
	return pvscsi_read32(PVSCSI_REG_COMMAND_STATUS);
}

static void pvscsi_kick_rw(void) {
	pvscsi_write32(PVSCSI_REG_KICK_RW_IO, 0);
}

static void pvscsi_kick_non_rw(void) {
	pvscsi_write32(PVSCSI_REG_KICK_NON_RW_IO, 0);
}

static int pvscsi_execute_command(void *priv,
    const uint8_t *cdb, size_t cdb_len,
    void *data, size_t data_len, int direction)
{
	(void)priv;
	if (!g_pvscsi_ready || cdb_len > 16) return -1;

	uint32_t req_idx = g_rings_state->reqProdIdx & g_req_mask;
	pvscsi_req_desc_t *req = &g_req_ring[req_idx];
	memset(req, 0, sizeof(*req));
	req->context = 1;
	req->dataLen = (uint64_t)data_len;
	req->dataAddr = data && data_len ? virt_to_phys((uint64_t)(uintptr_t)data) : 0;
	req->senseLen = 0;
	req->flags = (direction == 1) ? PVSCSI_FLAG_CMD_DIR_TOHOST :
	             (direction == 2) ? PVSCSI_FLAG_CMD_DIR_TODEVICE : PVSCSI_FLAG_CMD_DIR_NONE;
	req->cdbLen = (uint8_t)cdb_len;
	memcpy(req->cdb, cdb, cdb_len);
	req->lun[1] = 0;
	req->tag = 0x20; /* SIMPLE_QUEUE_TAG */
	req->bus = 0;
	req->target = 0;

	/* Memory barrier: убедиться, что запись в req_ring видна до обновления reqProdIdx */
	__asm__ volatile("" ::: "memory");
	g_rings_state->reqProdIdx++;
	__asm__ volatile("" ::: "memory");

	if (direction != 0)
		pvscsi_kick_rw();
	else
		pvscsi_kick_non_rw();

	/* Poll completion: гипервизор обновляет cmpProdIdx */
	uint32_t cmp_cons = g_rings_state->cmpConsIdx;
	unsigned wait = 1000000; /* увеличил таймаут */
	while (wait--) {
		__asm__ volatile("" ::: "memory"); /* memory barrier перед чтением */
		if (g_rings_state->cmpProdIdx != cmp_cons) break;
		/* короткая задержка между проверками */
		for (volatile int i = 0; i < 100; i++);
	}
	__asm__ volatile("" ::: "memory");
	if (g_rings_state->cmpProdIdx == cmp_cons) {
		/* таймаут: возможно кольца не настроены или нет устройства */
		klogprintf("pvscsi: cmd timeout (cmpProdIdx=%u cmpConsIdx=%u reqProdIdx=%u)\n",
		           g_rings_state->cmpProdIdx, g_rings_state->cmpConsIdx, g_rings_state->reqProdIdx);
		return -1;
	}

	uint32_t cmp_idx = cmp_cons & g_cmp_mask;
	pvscsi_cmp_desc_t *cmp = &g_cmp_ring[cmp_idx];
	__asm__ volatile("" ::: "memory"); /* barrier перед чтением cmp */
	g_rings_state->cmpConsIdx = cmp_cons + 1;
	__asm__ volatile("" ::: "memory");

	if (cmp->context != 1) {
		klogprintf("pvscsi: bad context %llu (expected 1)\n", (unsigned long long)cmp->context);
		return -1;
	}
	if (cmp->hostStatus != BTSTAT_SUCCESS && cmp->hostStatus != BTSTAT_SELTIMEO) {
		klogprintf("pvscsi: hostStatus=0x%x scsiStatus=0x%x\n", cmp->hostStatus, cmp->scsiStatus);
		return -1;
	}
	if (cmp->scsiStatus != 0x00 && cmp->scsiStatus != 0x02) { /* GOOD / CHECK CONDITION */
		klogprintf("pvscsi: scsiStatus=0x%x (hostStatus=0x%x)\n", cmp->scsiStatus, cmp->hostStatus);
		return -1;
	}
	return 0;
}

static const scsi_transport_ops_t pvscsi_ops = {
	.execute_command = pvscsi_execute_command,
};

/* Инициализация и регистрация LUN. Вызывать после scsi_init() и devfs mount. */
int pvscsi_init(void) {
	pci_device_t *devs = pci_get_devices();
	int count = pci_get_device_count();
	pci_device_t *pdev = NULL;
	for (int i = 0; i < count; i++) {
		if (devs[i].vendor_id == PVSCSI_VENDOR_ID && devs[i].device_id == PVSCSI_DEVICE_ID) {
			pdev = &devs[i];
			break;
		}
	}
	if (!pdev) return 0;

	uint32_t cmd = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, 0x04);
	cmd |= (1u << 0) | (1u << 1) | (1u << 2);
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, 0x04, cmd);

	/* Регистры KICK на смещениях 0x3014 и 0x4018 — при I/O BAR диапазон портов
	   часто мал, гипервизор не получает kick и cmpProdIdx не обновляется.
	   Предпочитаем MMIO (BAR0 или BAR1), иначе I/O только если MMIO нет. */
	uint32_t bar0 = pdev->bar[0];
	uint32_t bar1 = pdev->bar[1];
	g_pvscsi_mmio = NULL;
	g_pvscsi_use_io = 0;
	uint64_t mmio_pa = 0;
	if (!(bar0 & 1) && bar0 != 0) {
		mmio_pa = (uint64_t)(bar0 & ~0xFULL);
	} else if (!(bar1 & 1) && bar1 != 0) {
		mmio_pa = (uint64_t)(bar1 & ~0xFULL);
	}
	if (mmio_pa != 0) {
		g_pvscsi_mmio = mmio_map_phys(mmio_pa, 0x10000);
		if (g_pvscsi_mmio) {
			klogprintf("pvscsi: using MMIO at 0x%llx\n", (unsigned long long)mmio_pa);
		}
	}
	if (!g_pvscsi_mmio && bar0 && (bar0 & 1)) {
		g_pvscsi_io_base = (uint16_t)(bar0 & ~3u);
		g_pvscsi_use_io = 1;
		klogprintf("pvscsi: using I/O ports base=0x%x (KICK may be out of range)\n", (unsigned)g_pvscsi_io_base);
	}
	if (!g_pvscsi_mmio && !g_pvscsi_use_io) {
		klogprintf("pvscsi: no usable BAR (BAR0=%08x BAR1=%08x)\n", (unsigned)bar0, (unsigned)bar1);
		return 0;
	}

	pvscsi_write_cmd(PVSCSI_CMD_ADAPTER_RESET, NULL, 0);
	uint32_t st = pvscsi_read_status();
	(void)st;

	void *raw_state, *raw_req, *raw_cmp;
	void *state_page = pvscsi_alloc_aligned(PVSCSI_PAGE_SIZE, PVSCSI_PAGE_SIZE, &raw_state);
	void *req_page  = pvscsi_alloc_aligned(PVSCSI_PAGE_SIZE, PVSCSI_PAGE_SIZE, &raw_req);
	void *cmp_page  = pvscsi_alloc_aligned(PVSCSI_PAGE_SIZE, PVSCSI_PAGE_SIZE, &raw_cmp);
	if (!state_page || !req_page || !cmp_page) {
		klogprintf("pvscsi: alloc rings failed\n");
		if (state_page) kfree(raw_state);
		if (req_page) kfree(raw_req);
		if (cmp_page) kfree(raw_cmp);
		return 0;
	}

	uint64_t state_pa = virt_to_phys((uint64_t)(uintptr_t)state_page);
	uint64_t req_pa   = virt_to_phys((uint64_t)(uintptr_t)req_page);
	uint64_t cmp_pa   = virt_to_phys((uint64_t)(uintptr_t)cmp_page);
	if (!state_pa || !req_pa || !cmp_pa) {
		klogprintf("pvscsi: virt_to_phys failed\n");
		kfree(raw_state); kfree(raw_req); kfree(raw_cmp);
		return 0;
	}

	g_rings_state = (pvscsi_rings_state_t *)state_page;
	g_req_ring    = (pvscsi_req_desc_t *)req_page;
	g_cmp_ring    = (pvscsi_cmp_desc_t *)cmp_page;
	memset(g_rings_state, 0, PVSCSI_PAGE_SIZE);
	memset(g_req_ring, 0, PVSCSI_PAGE_SIZE);
	memset(g_cmp_ring, 0, PVSCSI_PAGE_SIZE);

	/* 1 page req = 32 entries -> log2=5; 1 page cmp = 128 entries -> log2=7 */
	g_rings_state->reqNumEntriesLog2 = 5;
	g_rings_state->cmpNumEntriesLog2 = 7;
	/* Индексы должны быть 0 при инициализации */
	g_rings_state->reqProdIdx = 0;
	g_rings_state->reqConsIdx = 0;
	g_rings_state->cmpProdIdx = 0;
	g_rings_state->cmpConsIdx = 0;
	g_req_mask = (1u << 5) - 1;
	g_cmp_mask = (1u << 7) - 1;

	pvscsi_setup_rings_cmd_t setup;
	memset(&setup, 0, sizeof(setup));
	setup.reqRingNumPages = 1;
	setup.cmpRingNumPages = 1;
	setup.ringsStatePPN = state_pa >> 12;
	setup.reqRingPPNs[0] = req_pa >> 12;
	setup.cmpRingPPNs[0] = cmp_pa >> 12;
	pvscsi_write_cmd(PVSCSI_CMD_SETUP_RINGS, &setup, sizeof(setup) / 4);
	/* В Linux статус после SETUP_RINGS не проверяют; 0xFFFFFFFF может означать
	   «ещё обрабатывается» или особенность I/O-режима, а не «не поддерживается». */
	(void)pvscsi_read_status();
	/* Дать гипервизору время обработать SETUP_RINGS */
	pit_sleep_ms(10);

	g_pvscsi_ready = 1;
	klogprintf("pvscsi: controller at %02x:%02x.%x initialized\n",
	           pdev->bus, pdev->device, pdev->function);

	int id = scsi_register_lun(g_pvscsi_mmio, &pvscsi_ops, 0);
	if (id >= 0)
		klogprintf("pvscsi: SCSI disk registered as /dev/sd%c (disk_id=%d)\n",
		           (id < 26) ? ('a' + id) : '?', id);
	else
		klogprintf("pvscsi: no disk on target 0 lun 0 (TEST UNIT READY/INQUIRY failed)\n");
	return (id >= 0) ? 1 : 0;
}
