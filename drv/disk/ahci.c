#include <axonos.h>
#include <pci.h>
#include <mmio.h>
#include <disk.h>
#include <heap.h>
#include <string.h>
#include <devfs.h>
#include <fat32.h>
#include <ramfs.h>
#include <ahci.h>
#include <paging.h>
#include <pit.h>

/* AHCI SATA driver (minimal but functional).
   - Discovers AHCI controllers via PCI class/subclass/prog_if.
   - Initializes SATA (ATA) ports.
   - Issues ATA IDENTIFY to get device size.
   - Provides disk_ops read/write via AHCI DMA (polling).

   This is intentionally simple (no interrupts, no NCQ, no hotplug). */

/* HBA global registers */
#define AHCI_REG_CAP    0x00
#define AHCI_REG_GHC    0x04
#define AHCI_REG_IS     0x08
#define AHCI_REG_PI     0x0C

/* GHC bits */
#define AHCI_GHC_HR     (1u << 0)
#define AHCI_GHC_IE     (1u << 1)
#define AHCI_GHC_AE     (1u << 31)

/* BOHC bits (BIOS/OS handoff control) */
#define AHCI_BOHC_BOS   (1u << 0)  /* BIOS owned semaphore */
#define AHCI_BOHC_OOS   (1u << 1)  /* OS owned semaphore */
#define AHCI_BOHC_BB    (1u << 4)  /* BIOS busy */

/* Port register bits / offsets (within port) */
#define AHCI_PORT_BASE  0x100
#define AHCI_PORT_SIZE  0x80

#define PxCLB   0x00
#define PxCLBU  0x04
#define PxFB    0x08
#define PxFBU   0x0C
#define PxIS    0x10
#define PxIE    0x14
#define PxCMD   0x18
#define PxTFD   0x20
#define PxSIG   0x24
#define PxSSTS  0x28
#define PxSCTL  0x2C
#define PxSERR  0x30
#define PxSACT  0x34
#define PxCI    0x38

/* PxIS bits we care about */
#define PxIS_HBDS   (1u << 28) /* Host Bus Data Error */
#define PxIS_HBFS   (1u << 29) /* Host Bus Fatal Error */
#define PxIS_TFES   (1u << 30) /* Task File Error Status */

/* PxCMD bits */
#define PxCMD_ST    (1u << 0)
#define PxCMD_SUD   (1u << 1)
#define PxCMD_POD   (1u << 2)
#define PxCMD_CLO   (1u << 3)
#define PxCMD_FRE   (1u << 4)
#define PxCMD_FR    (1u << 14)
#define PxCMD_CR    (1u << 15)
/* Interface Communication Control (ICC) bits 28..31 should normally be 0 (idle). */
#define PxCMD_ICC_MASK (0xFu << 28)

/* SATA signatures */
#define SATA_SIG_ATA    0x00000101
#define SATA_SIG_ATAPI  0xEB140101
#define SATA_SIG_SEMB   0xC33C0101
#define SATA_SIG_PM     0x96690101

/* FIS types */
#define FIS_TYPE_REG_H2D 0x27

/* ATA commands */
#define ATA_CMD_IDENTIFY        0xEC
#define ATA_CMD_READ_DMA_EXT    0x25
#define ATA_CMD_WRITE_DMA_EXT   0x35

/* Max command slots */
#define AHCI_MAX_SLOTS 32

extern uint64_t virt_to_phys(uint64_t va);

typedef volatile struct {
	uint32_t clb;
	uint32_t clbu;
	uint32_t fb;
	uint32_t fbu;
	uint32_t is;
	uint32_t ie;
	uint32_t cmd;
	uint32_t rsv0;
	uint32_t tfd;
	uint32_t sig;
	uint32_t ssts;
	uint32_t sctl;
	uint32_t serr;
	uint32_t sact;
	uint32_t ci;
	uint32_t sntf;
	uint32_t fbs;
	uint32_t rsv1[11];
	uint32_t vendor[4];
} hba_port_t;

typedef volatile struct {
	uint32_t cap;
	uint32_t ghc;
	uint32_t is;
	uint32_t pi;
	uint32_t vs;
	uint32_t ccc_ctl;
	uint32_t ccc_pts;
	uint32_t em_loc;
	uint32_t em_ctl;
	uint32_t cap2;
	uint32_t bohc;
	uint8_t  rsv[0xA0 - 0x2C];
	uint8_t  vendor[0x100 - 0xA0];
	hba_port_t ports[32];
} hba_mem_t;

/* Command header is 32 bytes. Avoid C bitfields (layout is implementation-defined). */
typedef struct __attribute__((packed)) {
	uint32_t dw0;           /* CFL/A/W/P/R/B/C/PMP/PRDTL */
	volatile uint32_t prdbc;
	uint32_t ctba;
	uint32_t ctbau;
	uint32_t rsv1[4];
} hba_cmd_header_t;

/* dw0 helpers */
#define CMDH_CFL(n)        ((uint32_t)((n) & 0x1Fu) << 0)
#define CMDH_W             (1u << 6)
/* Clear busy upon R_OK (helps some controllers finalize PIO-in commands cleanly) */
#define CMDH_C             (1u << 10)
#define CMDH_PMP(n)        ((uint32_t)((n) & 0xFu) << 12)
#define CMDH_PRDTL(n)      ((uint32_t)((n) & 0xFFFFu) << 16)

typedef struct __attribute__((packed)) {
	uint32_t dba;
	uint32_t dbau;
	uint32_t rsv0;
	uint32_t dbc; /* bits 0..21: byte count-1, bit 31: interrupt */
} hba_prdt_entry_t;

#define PRDT_DBC(bytes)    ((uint32_t)(((bytes) - 1u) & 0x003FFFFFu))
#define PRDT_I             (1u << 31)

typedef struct __attribute__((packed)) {
	uint8_t  fis_type;
	uint8_t  pmport : 4;
	uint8_t  rsv0   : 3;
	uint8_t  c      : 1;
	uint8_t  command;
	uint8_t  featurel;
	uint8_t  lba0;
	uint8_t  lba1;
	uint8_t  lba2;
	uint8_t  device;
	uint8_t  lba3;
	uint8_t  lba4;
	uint8_t  lba5;
	uint8_t  featureh;
	uint8_t  countl;
	uint8_t  counth;
	uint8_t  icc;
	uint8_t  control;
	uint8_t  rsv1[4];
} fis_reg_h2d_t;

typedef struct __attribute__((packed)) {
	uint8_t cfis[64];
	uint8_t acmd[16];
	uint8_t rsv[48];
	hba_prdt_entry_t prdt[1];
} hba_cmd_table_t;

typedef struct {
	int used;
	hba_mem_t *hba;
	uint64_t hba_phys;
	int port_no;
	uint32_t sig;
	uint32_t sectors;
	char model[41];
	/* allocated regions */
	void *clb_mem;
	void *fb_mem;
	void *ctba_mem[AHCI_MAX_SLOTS];
} ahci_port_state_t;

static ahci_port_state_t g_ports[DISK_MAX_DEVICES]; /* indexed by disk device_id */
static int g_ports_inited = 0;

/* forward declarations (used by recovery paths) */
static int ahci_port_start(hba_port_t *p);
static int ahci_port_comreset(hba_port_t *p);

static void *kmalloc_aligned(size_t size, size_t align) {
	/* Simple align helper (leaks the base pointer; acceptable for kernel lifetime objects). */
	uintptr_t raw = (uintptr_t)kmalloc(size + align);
	if (!raw) return NULL;
	uintptr_t aligned = (raw + (align - 1)) & ~(uintptr_t)(align - 1);
	memset((void*)aligned, 0, size);
	return (void*)aligned;
}

static inline void ahci_port_stop(hba_port_t *p) {
	if (!p) return;
	/* Clear ST */
	p->cmd &= ~PxCMD_ST;
	/* Wait for CR to clear */
	for (int i = 0; i < 1000000; i++) {
		if ((p->cmd & PxCMD_CR) == 0) break;
		asm volatile("pause");
	}
	/* Clear FRE */
	p->cmd &= ~PxCMD_FRE;
	/* Wait for FR to clear */
	for (int i = 0; i < 1000000; i++) {
		if ((p->cmd & PxCMD_FR) == 0) break;
		asm volatile("pause");
	}
}

/* Try to recover a stuck/non-starting port engine. */
static int ahci_port_recover(hba_port_t *p) {
	if (!p) return -1;
	/* Stop engine */
	ahci_port_stop(p);
	/* Clear errors/interrupts */
	{
		uint32_t is = p->is;
		if (is) p->is = is;
		uint32_t serr = p->serr;
		if (serr) p->serr = serr;
	}
	/* Command list override: attempts to clear BSY/DRQ state */
	p->cmd |= PxCMD_CLO;
	for (int i = 0; i < 2000; i++) {
		if ((p->cmd & PxCMD_CLO) == 0) break;
		pit_sleep_ms(1);
	}
	/* COMRESET the link */
	(void)ahci_port_comreset(p);
	/* Start again */
	return ahci_port_start(p);
}

/* Full port recovery that also reprograms CLB/FB (can be cleared by resets)
   and clears fatal bus error bits that prevent PxCI writes from sticking. */
static int ahci_port_recover_full(ahci_port_state_t *st) {
	if (!st || !st->hba) return -1;
	hba_port_t *p = &st->hba->ports[st->port_no];

	ahci_port_stop(p);

	uint64_t clb_pa = virt_to_phys((uint64_t)(uintptr_t)st->clb_mem);
	uint64_t fb_pa  = virt_to_phys((uint64_t)(uintptr_t)st->fb_mem);
	if (!clb_pa || !fb_pa) return -1;

	/* Program hi then lo (some emulators are picky). */
	p->clbu = (uint32_t)(clb_pa >> 32);
	p->clb  = (uint32_t)(clb_pa & 0xFFFFFFFFu);
	p->fbu  = (uint32_t)(fb_pa >> 32);
	p->fb   = (uint32_t)(fb_pa & 0xFFFFFFFFu);

	/* Clear global + port interrupts/errors (RWC). */
	{
		uint32_t is = p->is;
		if (is) p->is = is;
		uint32_t serr = p->serr;
		if (serr) p->serr = serr;
	}

	/* Try CLO and COMRESET. */
	p->cmd &= ~PxCMD_ICC_MASK;
	p->cmd |= PxCMD_CLO;
	for (int i = 0; i < 2000; i++) {
		if ((p->cmd & PxCMD_CLO) == 0) break;
		pit_sleep_ms(1);
	}
	(void)ahci_port_comreset(p);
	return ahci_port_start(p);
}

static int ahci_port_start(hba_port_t *p) {
	if (!p) return -1;
	/* Power on + spin up if supported, enable FIS receive then start.
	   Many controllers (incl. VMware) require waiting for FR/CR to reflect state. */
	/* Ensure ICC idle and clear CLO before enabling. */
	p->cmd &= ~(PxCMD_ICC_MASK | PxCMD_CLO);
	p->cmd |= PxCMD_POD | PxCMD_SUD;
	/* Enable FIS receive */
	p->cmd |= PxCMD_FRE;
	for (int i = 0; i < 1000000; i++) {
		if (p->cmd & PxCMD_FR) break;
		asm volatile("pause");
	}
	/* Start command engine */
	p->cmd |= PxCMD_ST;
	for (int i = 0; i < 1000000; i++) {
		if (p->cmd & PxCMD_CR) break;
		asm volatile("pause");
	}
	/* CR must be set if engine started */
	if ((p->cmd & PxCMD_CR) == 0) return -2;
	return 0;
}

/* Issue COMRESET on port and wait for device. */
static int ahci_port_comreset(hba_port_t *p) {
	if (!p) return -1;
	/* DET=1 (COMRESET), then DET=0 */
	uint32_t sctl = p->sctl;
	p->sctl = (sctl & ~0x0Fu) | 0x1u;
	pit_sleep_ms(2);
	p->sctl = (sctl & ~0x0Fu) | 0x0u;
	/* wait for DET==3 */
	for (int i = 0; i < 2000; i++) {
		uint32_t ssts = p->ssts;
		uint32_t det = ssts & 0x0F;
		if (det == 0x3) return 0;
		pit_sleep_ms(1);
	}
	return -1;
}

static void ahci_hba_reset_and_handoff(hba_mem_t *hba) {
	if (!hba) return;
	/* BIOS/OS handoff if implemented */
	uint32_t cap2 = hba->cap2;
	if (cap2 & 0x1u) {
		uint32_t bohc = hba->bohc;
		/* Request OS ownership */
		bohc |= AHCI_BOHC_OOS;
		hba->bohc = bohc;
		/* Wait for BIOS to release ownership and finish busy work */
		for (int i = 0; i < 2000; i++) {
			uint32_t b = hba->bohc;
			if ((b & AHCI_BOHC_BOS) == 0 && (b & AHCI_BOHC_BB) == 0) break;
			pit_sleep_ms(1);
		}
	}

	/* Global HBA reset (HR) */
	hba->ghc |= AHCI_GHC_HR;
	for (int i = 0; i < 2000; i++) {
		if ((hba->ghc & AHCI_GHC_HR) == 0) break;
		pit_sleep_ms(1);
	}
	/* Enable AHCI mode after reset */
	hba->ghc |= AHCI_GHC_AE;
	hba->ghc &= ~AHCI_GHC_IE;
	/* Clear global interrupts */
	hba->is = 0xFFFFFFFFu;
}

static int ahci_port_wait_ready(hba_port_t *p) {
	if (!p) return -1;
	/* Wait until BSY and DRQ cleared in TFD */
	for (int i = 0; i < 1000000; i++) {
		uint32_t tfd = p->tfd;
		if ((tfd & (0x80u | 0x08u)) == 0) return 0; /* BSY|DRQ */
		asm volatile("pause");
	}
	return -1;
}

static int ahci_find_free_slot(hba_port_t *p) {
	uint32_t slots = p->sact | p->ci;
	for (int i = 0; i < AHCI_MAX_SLOTS; i++) {
		if ((slots & (1u << i)) == 0) return i;
	}
	return -1;
}

static int ahci_issue_cmd(ahci_port_state_t *st, int slot, uint32_t expect_min_prdbc) {
	hba_port_t *p = &st->hba->ports[st->port_no];
	/* If engine not running or port is in fatal bus error state, do full recovery. */
	if ((p->cmd & PxCMD_CR) == 0 || (p->is & (PxIS_HBFS | PxIS_HBDS | PxIS_TFES)) != 0) {
		int rr = ahci_port_recover_full(st);
		if (rr != 0) return -3;
	}
	/* Clear global + port interrupts/errors (RWC: write back the bits that are set). */
	if (st->hba) {
		uint32_t gis = st->hba->is;
		if (gis) st->hba->is = gis;
	}
	{
		uint32_t is = p->is;
		if (is) p->is = is;
		uint32_t serr = p->serr;
		if (serr) p->serr = serr;
	}
	/* Issue command */
	uint32_t bit = (1u << slot);
	p->ci = bit;
	/* Poll for completion */
	for (int i = 0; i < 5000000; i++) {
		/* TFES means command failed. */
		if (p->is & PxIS_TFES) return -1;
		/* Completion can be observed either by CI bit clear or D2H interrupt status. */
		if ((p->ci & bit) == 0) break;
		if (p->is & 0x00000002u) break; /* DHRS */
		/* If error bit in IS, abort */
		asm volatile("pause");
	}
	/* Hard timeout: command never completed. */
	if ((p->ci & bit) != 0 && (p->is & 0x00000002u) == 0) {
		/* Try hard recovery once on timeout. */
		(void)ahci_port_recover_full(st);
		return -2;
	}
	/* Check task file error */
	if (p->tfd & 0x01u) return -1;
	/* PRDBC is unreliable on some virtual AHCI implementations (VMware often leaves it 0
	   even for successful transfers). Keep it for diagnostics only; do not fail. */
	if (expect_min_prdbc > 0) {
		hba_cmd_header_t *cmd_list = (hba_cmd_header_t*)st->clb_mem;
		uint32_t prdbc = cmd_list[slot].prdbc;
		if (prdbc < expect_min_prdbc) {
			klogprintf("ahci: short transfer port=%d slot=%d prdbc=%u expect=%u IS=0x%08x TFD=0x%08x CI=0x%08x\n",
			           st->port_no, slot, prdbc, expect_min_prdbc, p->is, p->tfd, p->ci);
		}
	}
	return 0;
}

static int ahci_identify(ahci_port_state_t *st) {
	hba_port_t *p = &st->hba->ports[st->port_no];
	/* Clear stale errors/interrupts before issuing a new command */
	p->serr = 0xFFFFFFFFu;
	p->is = 0xFFFFFFFFu;
	if (ahci_port_wait_ready(p) != 0) return -1;

	int slot = ahci_find_free_slot(p);
	if (slot < 0) return -1;

	/* IMPORTANT: clb/ctba registers hold *physical* addresses. Do not treat them as
	   virtual pointers unless the heap is identity-mapped. Use our saved virtual
	   pointers instead. */
	hba_cmd_header_t *cmd_list = (hba_cmd_header_t*)st->clb_mem;
	hba_cmd_header_t *hdr = &cmd_list[slot];
	/* preserve command table physical pointer set during init */
	uint32_t saved_ctba = hdr->ctba;
	uint32_t saved_ctbau = hdr->ctbau;
	memset((void*)hdr, 0, sizeof(*hdr));
	hdr->ctba = saved_ctba;
	hdr->ctbau = saved_ctbau;
	hdr->dw0 = CMDH_CFL(sizeof(fis_reg_h2d_t) / 4) | CMDH_PMP(0) | CMDH_C | CMDH_PRDTL(1);
	hdr->prdbc = 0;

	/* command table */
	hba_cmd_table_t *tbl = (hba_cmd_table_t*)st->ctba_mem[slot];
	memset((void*)tbl, 0, 256);

	/* identify buffer */
	uint16_t *idbuf = (uint16_t*)kmalloc_aligned(512, 4096);
	if (!idbuf) return -1;
	uint64_t id_pa = virt_to_phys((uint64_t)(uintptr_t)idbuf);
	if (!id_pa) return -1;
	tbl->prdt[0].dba = (uint32_t)(id_pa & 0xFFFFFFFFu);
	tbl->prdt[0].dbau = (uint32_t)(id_pa >> 32);
	tbl->prdt[0].dbc = PRDT_DBC(512) | PRDT_I;

	fis_reg_h2d_t *fis = (fis_reg_h2d_t*)tbl->cfis;
	memset(fis, 0, sizeof(*fis));
	fis->fis_type = FIS_TYPE_REG_H2D;
	fis->c = 1;
	fis->command = ATA_CMD_IDENTIFY;
	fis->device = 0;

	if (ahci_issue_cmd(st, slot, 512) != 0) {
		return -1;
	}

	/* Parse total sectors (LBA48 words 100-103) */
	uint64_t lba48 =
		((uint64_t)idbuf[100]) |
		((uint64_t)idbuf[101] << 16) |
		((uint64_t)idbuf[102] << 32) |
		((uint64_t)idbuf[103] << 48);
	uint32_t sectors = (lba48 != 0) ? (uint32_t)(lba48 > 0xFFFFFFFFu ? 0xFFFFFFFFu : lba48)
	                                : ((uint32_t)idbuf[60] | ((uint32_t)idbuf[61] << 16));
	st->sectors = sectors;

	/* Model string words 27..46, bytes swapped within each word */
	char model[41];
	int mi = 0;
	for (int w = 27; w <= 46 && mi < 40; w++) {
		uint16_t v = idbuf[w];
		char a = (char)((v >> 8) & 0xFF);
		char b = (char)(v & 0xFF);
		model[mi++] = a;
		if (mi < 40) model[mi++] = b;
	}
	model[40] = '\0';
	/* trim trailing spaces */
	for (int t = 39; t >= 0; t--) {
		if (model[t] == ' ' || model[t] == '\0') model[t] = '\0';
		else break;
	}
	strncpy(st->model, model, sizeof(st->model) - 1);
	st->model[sizeof(st->model) - 1] = '\0';

	return 0;
}

static int ahci_rw(int device_id, uint32_t lba, void *buf, uint32_t sectors, int is_write) {
	if (device_id < 0 || device_id >= DISK_MAX_DEVICES) return -1;
	ahci_port_state_t *st = &g_ports[device_id];
	if (!st->used) return -1;
	if (!buf || sectors == 0) return 0;

	hba_port_t *p = &st->hba->ports[st->port_no];
	if (ahci_port_wait_ready(p) != 0) return -1;

	/* limit per-command sectors to avoid huge PRDT */
	const uint32_t max_sectors = 128; /* 64KiB */
	uint8_t *bp = (uint8_t*)buf;
	uint32_t done = 0;
	while (done < sectors) {
		uint32_t nsec = (sectors - done) > max_sectors ? max_sectors : (sectors - done);

		int slot = ahci_find_free_slot(p);
		if (slot < 0) return -1;

		hba_cmd_header_t *cmd_list = (hba_cmd_header_t*)st->clb_mem;
		hba_cmd_header_t *hdr = &cmd_list[slot];
		uint32_t saved_ctba = hdr->ctba;
		uint32_t saved_ctbau = hdr->ctbau;
		memset((void*)hdr, 0, sizeof(*hdr));
		hdr->ctba = saved_ctba;
		hdr->ctbau = saved_ctbau;
		hdr->dw0 = CMDH_CFL(sizeof(fis_reg_h2d_t) / 4) |
		           CMDH_PMP(0) |
		           CMDH_C |
		           (is_write ? CMDH_W : 0) |
		           CMDH_PRDTL(1);
		hdr->prdbc = 0;

		hba_cmd_table_t *tbl = (hba_cmd_table_t*)st->ctba_mem[slot];
		memset((void*)tbl, 0, 256);

		uint64_t pa = virt_to_phys((uint64_t)(uintptr_t)bp);
		if (!pa) return -1;
		tbl->prdt[0].dba = (uint32_t)(pa & 0xFFFFFFFFu);
		tbl->prdt[0].dbau = (uint32_t)(pa >> 32);
		tbl->prdt[0].dbc = PRDT_DBC(nsec * 512u) | PRDT_I;

		fis_reg_h2d_t *fis = (fis_reg_h2d_t*)tbl->cfis;
		memset(fis, 0, sizeof(*fis));
		fis->fis_type = FIS_TYPE_REG_H2D;
		fis->c = 1;
		fis->command = is_write ? ATA_CMD_WRITE_DMA_EXT : ATA_CMD_READ_DMA_EXT;
		uint64_t l = (uint64_t)lba + (uint64_t)done;
		fis->lba0 = (uint8_t)(l & 0xFF);
		fis->lba1 = (uint8_t)((l >> 8) & 0xFF);
		fis->lba2 = (uint8_t)((l >> 16) & 0xFF);
		fis->lba3 = (uint8_t)((l >> 24) & 0xFF);
		fis->lba4 = (uint8_t)((l >> 32) & 0xFF);
		fis->lba5 = (uint8_t)((l >> 40) & 0xFF);
		fis->device = 1u << 6; /* LBA */
		fis->countl = (uint8_t)(nsec & 0xFF);
		fis->counth = (uint8_t)((nsec >> 8) & 0xFF);

		/* Some virtual AHCI controllers don't update PRDBC for host-to-device DMA writes.
		   Require PRDBC only for reads; for writes rely on CI/TFD/IS completion checks. */
		uint32_t expect = is_write ? 0u : (nsec * 512u);
		if (ahci_issue_cmd(st, slot, expect) != 0) return -1;

		bp += nsec * 512u;
		done += nsec;
	}
	return 0;
}

static int ahci_read(int device_id, uint32_t lba, void *buf, uint32_t sectors) {
	return ahci_rw(device_id, lba, buf, sectors, 0);
}

static int ahci_write(int device_id, uint32_t lba, const void *buf, uint32_t sectors) {
	return ahci_rw(device_id, lba, (void*)buf, sectors, 1);
}

static int ahci_init_port(ahci_port_state_t *st) {
	hba_port_t *p = &st->hba->ports[st->port_no];

	ahci_port_stop(p);

	/* Clear errors and interrupts early. */
	p->serr = 0xFFFFFFFFu;
	p->is = 0xFFFFFFFFu;

	/* allocate command list (1K aligned) and FIS (256 aligned) */
	void *clb = kmalloc_aligned(1024, 1024);
	void *fb = kmalloc_aligned(256, 256);
	if (!clb || !fb) return -1;
	st->clb_mem = clb;
	st->fb_mem = fb;

	uint64_t clb_pa = virt_to_phys((uint64_t)(uintptr_t)clb);
	uint64_t fb_pa  = virt_to_phys((uint64_t)(uintptr_t)fb);
	if (!clb_pa || !fb_pa) {
		klogprintf("ahci: port %d: virt_to_phys failed for CLB/FB (clb=%p fb=%p clb_pa=0x%llx fb_pa=0x%llx)\n",
		           st->port_no, clb, fb,
		           (unsigned long long)clb_pa, (unsigned long long)fb_pa);
		return -1;
	}
	/* Program hi then lo (some emulators are picky). */
	p->clbu = (uint32_t)(clb_pa >> 32);
	p->clb  = (uint32_t)(clb_pa & 0xFFFFFFFFu);
	p->fbu  = (uint32_t)(fb_pa >> 32);
	p->fb   = (uint32_t)(fb_pa & 0xFFFFFFFFu);

	/* command tables per slot */
	hba_cmd_header_t *hdr = (hba_cmd_header_t*)clb;
	for (int i = 0; i < AHCI_MAX_SLOTS; i++) {
		void *ct = kmalloc_aligned(256, 128);
		if (!ct) return -1;
		st->ctba_mem[i] = ct;
		uint64_t ct_pa = virt_to_phys((uint64_t)(uintptr_t)ct);
		if (!ct_pa) {
			klogprintf("ahci: port %d: virt_to_phys failed for CT[%d] (ct=%p)\n",
			           st->port_no, i, ct);
			return -1;
		}
		hdr[i].ctba = (uint32_t)(ct_pa & 0xFFFFFFFFu);
		hdr[i].ctbau = (uint32_t)(ct_pa >> 32);
		/* clear dw0; filled per-command */
		hdr[i].dw0 = 0;
		hdr[i].prdbc = 0;
	}

	/* clear errors and interrupts */
	p->serr = 0xFFFFFFFFu;
	p->is = 0xFFFFFFFFu;
	p->ie = 0;

	/* COMRESET helps VMware/real hw transition device to ready state. */
	(void)ahci_port_comreset(p);

	int sr = ahci_port_start(p);
	if (sr != 0) {
		klogprintf("ahci: port %d: failed to start engine (sr=%d) CMD=0x%08x TFD=0x%08x SERR=0x%08x IS=0x%08x SSTS=0x%08x CLB=0x%08x%08x FB=0x%08x%08x\n",
		           st->port_no, sr,
		           p->cmd, p->tfd, p->serr, p->is, p->ssts,
		           p->clbu, p->clb, p->fbu, p->fb);
		return -1;
	}
	return 0;
}

static int ahci_register_disk(int controller_idx, int port_no, hba_mem_t *hba, uint64_t hba_phys) {
	disk_ops_t *ops = (disk_ops_t *)kmalloc(sizeof(disk_ops_t));
	if (!ops) return -1;
	memset(ops, 0, sizeof(*ops));

	char namebuf[32];
	snprintf(namebuf, sizeof(namebuf), "sata%d%c", controller_idx, (char)('a' + port_no));
	ops->name = (const char*)kmalloc(strlen(namebuf) + 1);
	if (ops->name) strcpy((char*)ops->name, namebuf);
	ops->init = NULL;
	ops->read = ahci_read;
	ops->write = ahci_write;

	int id = disk_register(ops);
	if (id < 0) {
		kfree((void*)ops->name);
		kfree(ops);
		return -1;
	}

	if (id >= 0 && id < DISK_MAX_DEVICES) {
		ahci_port_state_t *st = &g_ports[id];
		memset(st, 0, sizeof(*st));
		st->used = 1;
		st->hba = hba;
		st->hba_phys = hba_phys;
		st->port_no = port_no;
		st->sig = hba->ports[port_no].sig;
		if (ahci_init_port(st) == 0) {
			int ok = -1;
			for (int tries = 0; tries < 3; tries++) {
				ok = ahci_identify(st);
				if (ok == 0 && st->sectors != 0) break;
				/* dump basic port state for diagnosis */
				hba_port_t *p = &st->hba->ports[st->port_no];
				klogprintf("ahci: identify failed port=%d try=%d TFD=0x%08x SERR=0x%08x IS=0x%08x SSTS=0x%08x CMD=0x%08x SIG=0x%08x CI=0x%08x SACT=0x%08x\n",
				           st->port_no, tries, p->tfd, p->serr, p->is, p->ssts, p->cmd, p->sig, p->ci, p->sact);
				ahci_port_stop(p);
				(void)ahci_port_comreset(p);
				(void)ahci_port_start(p);
				pit_sleep_ms(10);
			}
			/* Quick sanity read of LBA0 to distinguish "empty disk" from transport failure. */
			if (st->sectors > 0) {
				uint8_t sec0[512];
				memset(sec0, 0, sizeof(sec0));
				int rr0 = ahci_rw(id, 0, sec0, 1, 0);
				if (rr0 == 0) {
					int all_zero = 1;
					for (size_t bi = 0; bi < sizeof(sec0); bi++) {
						if (sec0[bi] != 0) { all_zero = 0; break; }
					}
					klogprintf("ahci: disk id=%d lba0: %02x %02x %02x %02x %02x %02x %02x %02x all_zero=%d\n",
					           id,
					           sec0[0], sec0[1], sec0[2], sec0[3],
					           sec0[4], sec0[5], sec0[6], sec0[7],
					           all_zero);
				} else {
					klogprintf("ahci: disk id=%d lba0 read failed rc=%d\n", id, rr0);
				}
			}
		}
	}

	/* /dev nodes: /dev/sdX like legacy */
	if (id >= 0 && id < 26) {
		char devpath[32];
		char letter = (char)('a' + id);
		snprintf(devpath, sizeof(devpath), "/dev/sd%c", letter);
		uint32_t secs = g_ports[id].sectors ? g_ports[id].sectors : 0xFFFFFFFFu;
		devfs_create_block_node(devpath, id, secs);
		/* Auto-mount intentionally disabled here: probing can wedge on some hypervisors.
		   Userspace can mount via SYS_mount (fat32/vfat/auto). */
	}

	klogprintf("ahci: registered disk id=%d port=%d model=\"%s\" sectors=%u\n",
	           id, port_no, g_ports[id].model[0] ? g_ports[id].model : "unknown",
	           g_ports[id].sectors);
	return id;
}

static int ahci_port_device_present(hba_port_t *p) {
	if (!p) return 0;
	uint32_t ssts = p->ssts;
	uint32_t det = ssts & 0x0F;
	uint32_t ipm = (ssts >> 8) & 0x0F;
	/* IPM can be Active(1), Partial(2), Slumber(6) on some hypervisors. */
	return (det == 0x3) && (ipm != 0x0);
}

int ahci_probe_and_register(void) {
	if (!g_ports_inited) {
		memset(g_ports, 0, sizeof(g_ports));
		g_ports_inited = 1;
	}

	int registered = 0;
	pci_device_t *devs = pci_get_devices();
	int count = pci_get_device_count();
	int ctrl_idx = 0;

	for (int i = 0; i < count; i++) {
		pci_device_t *pdev = &devs[i];
		if (!(pdev->class_code == 0x01 && pdev->subclass == 0x06 && pdev->prog_if == 0x01)) continue;

		/* Enable PCI memory decoding + bus mastering (required for AHCI DMA). */
		{
			uint32_t cmd = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, 0x04);
			cmd |= (1u << 0) | (1u << 1) | (1u << 2); /* IO | MEM | BUS MASTER */
			pci_config_write_dword(pdev->bus, pdev->device, pdev->function, 0x04, cmd);
		}

		/* Dump BARs for diagnosis and pick an MMIO BAR.
		   Some virtual controllers place ABAR in BAR0, others in BAR5. */
		uint64_t phys = 0;
		{
			klogprintf("ahci: pci %02x:%02x.%x bars: %08x %08x %08x %08x %08x %08x\n",
			           pdev->bus, pdev->device, pdev->function,
			           pdev->bar[0], pdev->bar[1], pdev->bar[2], pdev->bar[3], pdev->bar[4], pdev->bar[5]);
			for (int bi = 0; bi < 6; bi++) {
				uint32_t bar = pdev->bar[bi];
				if (bar == 0) continue;
				if (bar & 0x1u) continue; /* I/O BAR */
				uint32_t type = (bar >> 1) & 0x3u;
				if (type == 0x2u) {
					/* 64-bit BAR: combine with next BAR if present */
					if (bi + 1 < 6) {
						uint64_t lo = (uint64_t)(bar & ~0xFULL);
						uint64_t hi = (uint64_t)pdev->bar[bi + 1];
						phys = lo | (hi << 32);
						break;
					}
				} else {
					/* 32-bit memory BAR */
					phys = (uint64_t)(bar & ~0xFULL);
					break;
				}
			}
			/* Fallback to BAR5 if nothing selected */
			if (phys == 0 && pdev->bar[5]) phys = (uint64_t)(pdev->bar[5] & ~0xFULL);
		}
		if (phys == 0) continue;
		hba_mem_t *hba = (hba_mem_t*)mmio_map_phys(phys, 0x1100);
		if (!hba) {
			klogprintf("ahci: failed to map controller at 0x%llx\n", (unsigned long long)phys);
			continue;
		}

		/* Read a few registers early to sanity-check mapping. */
		uint32_t cap0 = hba->cap;
		uint32_t vs0  = hba->vs;
		uint32_t ghc0 = hba->ghc;

		/* Ensure ownership + reset, then enable AHCI mode */
		ahci_hba_reset_and_handoff(hba);

		uint32_t cap = hba->cap;
		uint32_t pi = hba->pi;
		if (pi == 0) continue;

		/* Some implementations report inconsistent CAP.NP; PI is usually reliable. */
		int n_ports = (int)((cap & 0x1Fu) + 1u);
		if (n_ports < 1) n_ports = 1;
		/* derive highest implemented port from PI */
		int pi_max = 0;
		for (int b = 31; b >= 0; b--) {
			if (pi & (1u << b)) { pi_max = b + 1; break; }
		}
		if (pi_max > n_ports) n_ports = pi_max;
		if (n_ports > 32) n_ports = 32;

		klogprintf("ahci: controller %02x:%02x.%x mmio=0x%llx CAP=0x%08x VS=0x%08x GHC=0x%08x PI=0x%08x\n",
		           pdev->bus, pdev->device, pdev->function,
		           (unsigned long long)phys, cap0, vs0, ghc0, pi);

		for (int port = 0; port < n_ports; port++) {
			if (!(pi & (1u << port))) continue;
			hba_port_t *p = &hba->ports[port];
			/* Some controllers report PI bits for ports that read as all-ones when unmapped. */
			if (p->ssts == 0xFFFFFFFFu || p->tfd == 0xFFFFFFFFu) continue;
			if (!ahci_port_device_present(p)) continue;
			uint32_t sig = p->sig;
			if (sig != SATA_SIG_ATA) continue; /* only SATA disks for now */
			if (ahci_register_disk(ctrl_idx, port, hba, phys) >= 0) registered++;
		}
		ctrl_idx++;
	}
	return registered;
}


