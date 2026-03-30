#include <axonos.h>
#include <pci.h>
#include <mmio.h>
#include <disk.h>
#include <devfs.h>
#include <scsi.h>
#include <heap.h>
#include <string.h>
#include <pit.h>
#include <paging.h>

#define NVME_PCI_CLASS_STORAGE 0x01
#define NVME_PCI_SUBCLASS_NVM  0x08
#define NVME_PCI_PROGIF_NVME   0x02

#define NVME_REG_CAP   0x0000
#define NVME_REG_VS    0x0008
#define NVME_REG_CC    0x0014
#define NVME_REG_CSTS  0x001C
#define NVME_REG_AQA   0x0024
#define NVME_REG_ASQ   0x0028
#define NVME_REG_ACQ   0x0030
#define NVME_REG_DBS   0x1000

#define NVME_CC_EN         (1u << 0)
#define NVME_CC_IOSQES_64  (6u << 16) /* 2^6 = 64 bytes */
#define NVME_CC_IOCQES_16  (4u << 20) /* 2^4 = 16 bytes */

#define NVME_CSTS_RDY      (1u << 0)

#define NVME_ADMIN_OPC_DELETE_IO_SQ 0x00
#define NVME_ADMIN_OPC_CREATE_IO_SQ 0x01
#define NVME_ADMIN_OPC_DELETE_IO_CQ 0x04
#define NVME_ADMIN_OPC_CREATE_IO_CQ 0x05
#define NVME_ADMIN_OPC_IDENTIFY     0x06
#define NVME_ADMIN_OPC_SET_FEATURES 0x09

#define NVME_NVM_OPC_WRITE 0x01
#define NVME_NVM_OPC_READ  0x02

#define NVME_CNS_IDENTIFY_NS          0x00
#define NVME_CNS_IDENTIFY_CTRL        0x01
#define NVME_CNS_ACTIVE_NS_ID_LIST    0x02
#define NVME_FEAT_NUM_QUEUES          0x07

#define NVME_ADMIN_QID 0

#define NVME_AQ_DEPTH 16
#define NVME_IO_DEPTH 64

#define NVME_TIMEOUT_MS 2000

extern uint64_t virt_to_phys(uint64_t va);

typedef struct __attribute__((packed)) {
	uint32_t cdw0;
	uint32_t nsid;
	uint64_t rsvd2;
	uint64_t mptr;
	uint64_t prp1;
	uint64_t prp2;
	uint32_t cdw10;
	uint32_t cdw11;
	uint32_t cdw12;
	uint32_t cdw13;
	uint32_t cdw14;
	uint32_t cdw15;
} nvme_sqe_t;

typedef struct __attribute__((packed)) {
	uint32_t dw0;
	uint32_t rsvd1;
	uint16_t sq_head;
	uint16_t sq_id;
	uint16_t cid;
	uint16_t status;
} nvme_cqe_t;

typedef struct {
	int used;
	volatile void *mmio;
	uint64_t mmio_phys;
	uint32_t db_stride;
	uint32_t nsid;
	uint32_t sectors; /* 512-byte sectors for disk layer */
	uint32_t lba_size;
	char model[41];
	char serial[21];

	nvme_sqe_t *admin_sq;
	nvme_cqe_t *admin_cq;
	nvme_sqe_t *io_sq;
	nvme_cqe_t *io_cq;

	uint16_t admin_sq_tail;
	uint16_t admin_cq_head;
	uint8_t  admin_cq_phase;

	uint16_t io_sq_tail;
	uint16_t io_cq_head;
	uint8_t  io_cq_phase;
	uint16_t io_qid;

	uint16_t next_cid;

	void *io_bounce;
} nvme_dev_t;

static nvme_dev_t g_nvme[DISK_MAX_DEVICES];
static int g_nvme_inited = 0;

static void *kmalloc_aligned(size_t size, size_t align) {
	uintptr_t raw = (uintptr_t)kmalloc(size + align);
	if (!raw) return NULL;
	uintptr_t aligned = (raw + (align - 1)) & ~(uintptr_t)(align - 1);
	memset((void*)aligned, 0, size);
	return (void*)aligned;
}

static inline uint64_t nvme_mmio_read64(volatile void *mmio, uint32_t off) {
	return mmio_read64(mmio, off);
}

static inline uint32_t nvme_mmio_read32(volatile void *mmio, uint32_t off) {
	return mmio_read32(mmio, off);
}

static inline void nvme_mmio_write64(volatile void *mmio, uint32_t off, uint64_t v) {
	mmio_write64((void*)mmio, off, v);
}

static inline void nvme_mmio_write32(volatile void *mmio, uint32_t off, uint32_t v) {
	mmio_write32((void*)mmio, off, v);
}

static inline uint16_t nvme_status_code(uint16_t status_field) {
	return (uint16_t)((status_field >> 1) & 0xFFu);
}

static inline uint16_t nvme_status_sct(uint16_t status_field) {
	return (uint16_t)((status_field >> 9) & 0x7u);
}

static inline int nvme_cqe_phase(const nvme_cqe_t *cqe) {
	return (int)(cqe->status & 0x1u);
}

static inline void nvme_ring_sq_db(nvme_dev_t *d, uint16_t qid, uint16_t tail) {
	uint32_t off = NVME_REG_DBS + (uint32_t)(2u * qid) * d->db_stride;
	nvme_mmio_write32(d->mmio, off, (uint32_t)tail);
}

static inline void nvme_ring_cq_db(nvme_dev_t *d, uint16_t qid, uint16_t head) {
	uint32_t off = NVME_REG_DBS + (uint32_t)(2u * qid + 1u) * d->db_stride;
	nvme_mmio_write32(d->mmio, off, (uint32_t)head);
}

static int nvme_wait_ready(nvme_dev_t *d, int ready) {
	for (int i = 0; i < NVME_TIMEOUT_MS; i++) {
		uint32_t csts = nvme_mmio_read32(d->mmio, NVME_REG_CSTS);
		int is_ready = (csts & NVME_CSTS_RDY) ? 1 : 0;
		if (is_ready == ready) return 0;
		pit_sleep_ms(1);
	}
	return -1;
}

static int nvme_submit_and_wait(nvme_dev_t *d,
                                int is_admin,
                                const nvme_sqe_t *cmd,
                                nvme_cqe_t *out_cqe) {
	nvme_sqe_t *sq = is_admin ? d->admin_sq : d->io_sq;
	nvme_cqe_t *cq = is_admin ? d->admin_cq : d->io_cq;
	uint16_t *sq_tail = is_admin ? &d->admin_sq_tail : &d->io_sq_tail;
	uint16_t *cq_head = is_admin ? &d->admin_cq_head : &d->io_cq_head;
	uint8_t *cq_phase = is_admin ? &d->admin_cq_phase : &d->io_cq_phase;
	uint16_t qid = is_admin ? NVME_ADMIN_QID : d->io_qid;
	uint16_t q_depth = is_admin ? NVME_AQ_DEPTH : NVME_IO_DEPTH;
	uint16_t cid = (uint16_t)(d->next_cid++);

	nvme_sqe_t c = *cmd;
	c.cdw0 &= 0x0000FFFFu;
	c.cdw0 |= ((uint32_t)cid << 16);

	uint16_t tail = *sq_tail;
	sq[tail] = c;
	__asm__ volatile("" ::: "memory");

	tail++;
	if (tail >= q_depth) tail = 0;
	*sq_tail = tail;
	nvme_ring_sq_db(d, qid, tail);

	for (int t = 0; t < NVME_TIMEOUT_MS * 2000; t++) {
		nvme_cqe_t *e = &cq[*cq_head];
		__asm__ volatile("" ::: "memory");
		if (nvme_cqe_phase(e) == *cq_phase) {
			nvme_cqe_t done = *e;
			uint16_t head = *cq_head + 1;
			if (head >= q_depth) {
				head = 0;
				*cq_phase ^= 1u;
			}
			*cq_head = head;
			nvme_ring_cq_db(d, qid, head);

			if (done.cid == cid) {
				if (out_cqe) *out_cqe = done;
				if (nvme_status_code(done.status) != 0) {
					klogprintf("nvme: cmd opc=0x%x failed cid=%u sct=%u sc=0x%x status=0x%x dw0=0x%x\n",
					           (unsigned)(c.cdw0 & 0xFFu), (unsigned)cid,
					           (unsigned)nvme_status_sct(done.status),
					           (unsigned)nvme_status_code(done.status),
					           (unsigned)done.status, (unsigned)done.dw0);
					return -2;
				}
				return 0;
			}
			/* unexpected completion; continue polling */
		}
		asm volatile("pause");
	}
	return -1;
}

static int nvme_identify(nvme_dev_t *d, uint32_t nsid, uint32_t cns, void *buf4k) {
	if (!d || !buf4k) return -1;
	uint64_t pa = virt_to_phys((uint64_t)(uintptr_t)buf4k);
	if (!pa) return -1;

	nvme_sqe_t cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.cdw0 = NVME_ADMIN_OPC_IDENTIFY;
	cmd.nsid = nsid;
	cmd.prp1 = pa;
	cmd.cdw10 = cns;

	return nvme_submit_and_wait(d, 1, &cmd, NULL);
}

static int nvme_set_number_of_queues(nvme_dev_t *d) {
	nvme_sqe_t cmd;
	nvme_cqe_t cqe;
	memset(&cmd, 0, sizeof(cmd));
	cmd.cdw0 = NVME_ADMIN_OPC_SET_FEATURES;
	cmd.cdw10 = NVME_FEAT_NUM_QUEUES;
	/* cdw11 is zero-based: 0 => request 1 submission + 1 completion queue. */
	cmd.cdw11 = 0;
	if (nvme_submit_and_wait(d, 1, &cmd, &cqe) != 0) return -1;
	klogprintf("nvme: queue feature result dw0=0x%x\n", (unsigned)cqe.dw0);
	return 0;
}

static void nvme_try_delete_queue_pair(nvme_dev_t *d, uint16_t qid) {
	nvme_sqe_t cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.cdw0 = NVME_ADMIN_OPC_DELETE_IO_SQ;
	cmd.cdw10 = qid;
	(void)nvme_submit_and_wait(d, 1, &cmd, NULL);
	memset(&cmd, 0, sizeof(cmd));
	cmd.cdw0 = NVME_ADMIN_OPC_DELETE_IO_CQ;
	cmd.cdw10 = qid;
	(void)nvme_submit_and_wait(d, 1, &cmd, NULL);
}

static uint64_t read_le64(const uint8_t *p) {
	return ((uint64_t)p[0]) |
	       ((uint64_t)p[1] << 8) |
	       ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) |
	       ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) |
	       ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}

static void nvme_trim_copy_ascii(char *dst, size_t dst_cap, const uint8_t *src, size_t src_len) {
	if (!dst || dst_cap == 0) return;
	size_t n = (src_len < (dst_cap - 1)) ? src_len : (dst_cap - 1);
	for (size_t i = 0; i < n; i++) {
		uint8_t c = src[i];
		dst[i] = (c >= 32 && c <= 126) ? (char)c : ' ';
	}
	dst[n] = '\0';
	for (int i = (int)n - 1; i >= 0; i--) {
		if (dst[i] == ' ' || dst[i] == '\0') dst[i] = '\0';
		else break;
	}
}

static int nvme_setup_admin_queues(nvme_dev_t *d) {
	d->admin_sq = (nvme_sqe_t*)kmalloc_aligned(NVME_AQ_DEPTH * sizeof(nvme_sqe_t), 4096);
	d->admin_cq = (nvme_cqe_t*)kmalloc_aligned(NVME_AQ_DEPTH * sizeof(nvme_cqe_t), 4096);
	if (!d->admin_sq || !d->admin_cq) return -1;

	uint64_t asq = virt_to_phys((uint64_t)(uintptr_t)d->admin_sq);
	uint64_t acq = virt_to_phys((uint64_t)(uintptr_t)d->admin_cq);
	if (!asq || !acq) return -1;

	/* Controller reset to a known state. */
	nvme_mmio_write32(d->mmio, NVME_REG_CC, 0);
	if (nvme_wait_ready(d, 0) != 0) return -1;

	uint32_t aqa = (uint32_t)((NVME_AQ_DEPTH - 1) | ((NVME_AQ_DEPTH - 1) << 16));
	nvme_mmio_write32(d->mmio, NVME_REG_AQA, aqa);
	nvme_mmio_write64(d->mmio, NVME_REG_ASQ, asq);
	nvme_mmio_write64(d->mmio, NVME_REG_ACQ, acq);

	uint32_t cc = NVME_CC_IOSQES_64 | NVME_CC_IOCQES_16 | NVME_CC_EN;
	nvme_mmio_write32(d->mmio, NVME_REG_CC, cc);
	if (nvme_wait_ready(d, 1) != 0) return -1;

	d->admin_sq_tail = 0;
	d->admin_cq_head = 0;
	d->admin_cq_phase = 1;
	return 0;
}

static int nvme_setup_io_queues(nvme_dev_t *d) {
	if (nvme_set_number_of_queues(d) != 0) {
		klogprintf("nvme: set features(number_of_queues) failed\n");
		return -1;
	}

	d->io_sq = (nvme_sqe_t*)kmalloc_aligned(NVME_IO_DEPTH * sizeof(nvme_sqe_t), 4096);
	d->io_cq = (nvme_cqe_t*)kmalloc_aligned(NVME_IO_DEPTH * sizeof(nvme_cqe_t), 4096);
	if (!d->io_sq || !d->io_cq) return -1;

	uint64_t iosq_pa = virt_to_phys((uint64_t)(uintptr_t)d->io_sq);
	uint64_t iocq_pa = virt_to_phys((uint64_t)(uintptr_t)d->io_cq);
	if (!iosq_pa || !iocq_pa) return -1;

	nvme_sqe_t cmd;
	const uint16_t qid_try[] = {1, 2, 3, 4};
	int ok = 0;
	for (size_t qi = 0; qi < sizeof(qid_try)/sizeof(qid_try[0]); qi++) {
		uint16_t qid = qid_try[qi];
		nvme_try_delete_queue_pair(d, qid);

		memset(&cmd, 0, sizeof(cmd));
		cmd.cdw0 = NVME_ADMIN_OPC_CREATE_IO_CQ;
		cmd.prp1 = iocq_pa;
		/* CDW10: bits 15:0 = QID, bits 31:16 = QSIZE (zero-based). */
		cmd.cdw10 = (uint32_t)(qid | ((NVME_IO_DEPTH - 1) << 16));
		cmd.cdw11 = 0x1; /* PC=1, polling mode */
		if (nvme_submit_and_wait(d, 1, &cmd, NULL) != 0) {
			continue;
		}

		memset(&cmd, 0, sizeof(cmd));
		cmd.cdw0 = NVME_ADMIN_OPC_CREATE_IO_SQ;
		cmd.prp1 = iosq_pa;
		/* CDW10: bits 15:0 = QID, bits 31:16 = QSIZE (zero-based). */
		cmd.cdw10 = (uint32_t)(qid | ((NVME_IO_DEPTH - 1) << 16));
		cmd.cdw11 = (uint32_t)((qid << 16) | 0x1); /* CQID=qid, PC=1 */
		if (nvme_submit_and_wait(d, 1, &cmd, NULL) != 0) {
			nvme_try_delete_queue_pair(d, qid);
			continue;
		}

		d->io_qid = qid;
		klogprintf("nvme: io queues created with qid=%u\n", (unsigned)qid);
		ok = 1;
		break;
	}
	if (!ok) {
		klogprintf("nvme: create io queues failed for qid set\n");
		return -1;
	}

	d->io_sq_tail = 0;
	d->io_cq_head = 0;
	d->io_cq_phase = 1;
	return 0;
}

static int nvme_readwrite_one(nvme_dev_t *d, uint64_t slba, void *buf512, int is_write) {
	if (!d || !buf512 || d->lba_size != 512) return -1;
	uint64_t pa = virt_to_phys((uint64_t)(uintptr_t)buf512);
	if (!pa) return -1;

	nvme_sqe_t cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.cdw0 = is_write ? NVME_NVM_OPC_WRITE : NVME_NVM_OPC_READ;
	cmd.nsid = d->nsid;
	cmd.prp1 = pa;
	cmd.cdw10 = (uint32_t)(slba & 0xFFFFFFFFu);
	cmd.cdw11 = (uint32_t)(slba >> 32);
	cmd.cdw12 = 0; /* NLB=0 -> one logical block */

	return nvme_submit_and_wait(d, 0, &cmd, NULL);
}

static int nvme_rw(int device_id, uint32_t lba, void *buf, uint32_t sectors, int is_write) {
	if (device_id < 0 || device_id >= DISK_MAX_DEVICES) return -1;
	nvme_dev_t *d = &g_nvme[device_id];
	if (!d->used) return -1;
	if (!buf || sectors == 0) return 0;
	if (d->lba_size != 512) return -1;
	if (!d->io_bounce) return -1;

	uint8_t *p = (uint8_t*)buf;
	for (uint32_t i = 0; i < sectors; i++) {
		if (is_write) memcpy(d->io_bounce, p + (size_t)i * 512u, 512);
		if (nvme_readwrite_one(d, (uint64_t)lba + i, d->io_bounce, is_write) != 0) return -1;
		if (!is_write) memcpy(p + (size_t)i * 512u, d->io_bounce, 512);
	}
	return 0;
}

static int nvme_read(int device_id, uint32_t lba, void *buf, uint32_t sectors) {
	return nvme_rw(device_id, lba, buf, sectors, 0);
}

static int nvme_write(int device_id, uint32_t lba, const void *buf, uint32_t sectors) {
	return nvme_rw(device_id, lba, (void*)buf, sectors, 1);
}

static int nvme_register_namespace(nvme_dev_t *dev, int ctrl_index) {
	disk_ops_t *ops = (disk_ops_t*)kmalloc(sizeof(disk_ops_t));
	if (!ops) return -1;
	memset(ops, 0, sizeof(*ops));

	char namebuf[32];
	snprintf(namebuf, sizeof(namebuf), "nvme%dn%u", ctrl_index, (unsigned)dev->nsid);
	ops->name = (const char*)kmalloc(strlen(namebuf) + 1);
	if (ops->name) strcpy((char*)ops->name, namebuf);
	ops->read = nvme_read;
	ops->write = nvme_write;

	int id = disk_register(ops);
	if (id < 0) {
		kfree((void*)ops->name);
		kfree(ops);
		return -1;
	}
	if (id < 0 || id >= DISK_MAX_DEVICES) return -1;

	g_nvme[id] = *dev;
	g_nvme[id].used = 1;
	g_nvme[id].io_bounce = kmalloc_aligned(4096, 4096);
	if (!g_nvme[id].io_bounce) return -1;

	char path[32];
	snprintf(path, sizeof(path), "/dev/nvme%dn%u", ctrl_index, (unsigned)dev->nsid);
	(void)devfs_create_block_node(path, id, g_nvme[id].sectors);

	if (id >= 0 && id < 26) {
		char sd[16];
		snprintf(sd, sizeof(sd), "/dev/sd%c", (char)('a' + id));
		(void)devfs_create_block_node(sd, id, g_nvme[id].sectors);
	}

	(void)scsi_register_disk_as_lun(id, g_nvme[id].sectors, "NVME   ",
	                                g_nvme[id].model[0] ? g_nvme[id].model : "NVMe Disk",
	                                "1.0 ");

	klogprintf("nvme: registered /dev/%s sectors=%u model=\"%s\"\n",
	           namebuf, g_nvme[id].sectors,
	           g_nvme[id].model[0] ? g_nvme[id].model : "unknown");
	return 0;
}

static int nvme_pick_bar(pci_device_t *pdev, uint64_t *out_phys) {
	if (!pdev || !out_phys) return -1;
	*out_phys = 0;
	for (int i = 0; i < 6; i++) {
		uint32_t bar = pdev->bar[i];
		if (!bar || (bar & 0x1u)) continue; /* not memory BAR */
		uint32_t type = (bar >> 1) & 0x3u;
		if (type == 0x2u) {
			if (i + 1 >= 6) return -1;
			uint64_t lo = (uint64_t)(bar & ~0xFULL);
			uint64_t hi = (uint64_t)pdev->bar[i + 1];
			*out_phys = lo | (hi << 32);
			return 0;
		}
		*out_phys = (uint64_t)(bar & ~0xFULL);
		return 0;
	}
	return -1;
}

static int nvme_init_one_controller(pci_device_t *pdev, int ctrl_index) {
	uint64_t bar_phys = 0;
	if (nvme_pick_bar(pdev, &bar_phys) != 0 || !bar_phys) return 0;

	/* Enable MEM + BUS MASTER. */
	uint32_t cmd = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, 0x04);
	cmd |= (1u << 1) | (1u << 2);
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, 0x04, cmd);

	volatile void *mmio = (volatile void*)mmio_map_phys(bar_phys, 0x4000);
	if (!mmio) {
		klogprintf("nvme: %02x:%02x.%x map failed\n", pdev->bus, pdev->device, pdev->function);
		return 0;
	}

	nvme_dev_t tmp;
	memset(&tmp, 0, sizeof(tmp));
	tmp.mmio = mmio;
	tmp.mmio_phys = bar_phys;
	uint64_t cap = nvme_mmio_read64(mmio, NVME_REG_CAP);
	uint32_t vs = nvme_mmio_read32(mmio, NVME_REG_VS);
	tmp.db_stride = (uint32_t)(4u << ((cap >> 32) & 0xFu));

	klogprintf("nvme: controller %02x:%02x.%x CAP=0x%llx VS=0x%x\n",
	           pdev->bus, pdev->device, pdev->function,
	           (unsigned long long)cap, vs);

	if (nvme_setup_admin_queues(&tmp) != 0) {
		klogprintf("nvme: admin queue init failed\n");
		return 0;
	}
	if (nvme_setup_io_queues(&tmp) != 0) {
		klogprintf("nvme: io queue init failed\n");
		return 0;
	}

	void *id_buf = kmalloc_aligned(4096, 4096);
	if (!id_buf) return 0;

	/* Identify Controller */
	if (nvme_identify(&tmp, 0, NVME_CNS_IDENTIFY_CTRL, id_buf) != 0) {
		klogprintf("nvme: identify controller failed\n");
		return 0;
	}
	{
		const uint8_t *id = (const uint8_t*)id_buf;
		nvme_trim_copy_ascii(tmp.serial, sizeof(tmp.serial), id + 4, 20);
		nvme_trim_copy_ascii(tmp.model, sizeof(tmp.model), id + 24, 40);
	}

	/* Find first active namespace */
	memset(id_buf, 0, 4096);
	if (nvme_identify(&tmp, 0, NVME_CNS_ACTIVE_NS_ID_LIST, id_buf) != 0) {
		klogprintf("nvme: identify ns list failed\n");
		return 0;
	}
	uint32_t nsid = 0;
	for (int i = 0; i < 1024; i++) {
		uint8_t *p = (uint8_t*)id_buf + i * 4;
		uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
		             ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
		if (v != 0) { nsid = v; break; }
	}
	if (nsid == 0) {
		klogprintf("nvme: no active namespaces\n");
		return 0;
	}
	tmp.nsid = nsid;

	/* Identify Namespace */
	memset(id_buf, 0, 4096);
	if (nvme_identify(&tmp, nsid, NVME_CNS_IDENTIFY_NS, id_buf) != 0) {
		klogprintf("nvme: identify namespace %u failed\n", nsid);
		return 0;
	}
	{
		const uint8_t *id = (const uint8_t*)id_buf;
		uint64_t nsze = read_le64(id + 0);
		uint8_t flbas = id[26];
		uint8_t fmt = flbas & 0x0Fu;
		size_t lbaf_off = 128u + (size_t)fmt * 4u;
		uint8_t lbads = (lbaf_off + 2 < 4096) ? id[lbaf_off + 2] : 9;
		uint32_t lba_size = (lbads <= 31) ? (1u << lbads) : 512u;
		tmp.lba_size = lba_size;
		if (lba_size != 512u) {
			klogprintf("nvme: unsupported lba size=%u (only 512)\n", lba_size);
			return 0;
		}
		uint64_t sec64 = nsze; /* lba size is 512, so sectors match */
		tmp.sectors = (sec64 > 0xFFFFFFFFULL) ? 0xFFFFFFFFu : (uint32_t)sec64;
	}

	if (tmp.sectors == 0) {
		klogprintf("nvme: namespace %u has zero sectors\n", nsid);
		return 0;
	}

	if (nvme_register_namespace(&tmp, ctrl_index) != 0) return 0;
	return 1;
}

int nvme_init(void) {
	if (!g_nvme_inited) {
		memset(g_nvme, 0, sizeof(g_nvme));
		g_nvme_inited = 1;
	}

	pci_device_t *devs = pci_get_devices();
	int count = pci_get_device_count();
	int registered = 0;
	int ctrl_index = 0;

	for (int i = 0; i < count; i++) {
		pci_device_t *pdev = &devs[i];
		if (pdev->class_code != NVME_PCI_CLASS_STORAGE) continue;
		if (pdev->subclass != NVME_PCI_SUBCLASS_NVM) continue;
		if (pdev->prog_if != NVME_PCI_PROGIF_NVME) continue;
		registered += nvme_init_one_controller(pdev, ctrl_index);
		ctrl_index++;
	}

	if (registered == 0) klogprintf("nvme: no namespaces registered\n");
	return registered;
}

