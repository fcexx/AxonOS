#include <acpi_powerbtn.h>

#include <idt.h>
#include <klog.h>
#include <pic.h>
#include <serial.h>
#include <string.h>
#include <power.h>
#include <vga.h>

/* Multiboot2 constants (duplicated from smp_madt.c for standalone init) */
#define MB2_MAGIC 0x36d76289u
#define MB2_TAG_ACPI_OLD 14u
#define MB2_TAG_ACPI_NEW 15u

/* FADT IA-PC flags (ACPI 6.x): bit 20 = HW_REDUCED_ACPI */
#define FADT_HW_REDUCED_ACPI (1u << 20)

struct acpi_sdt_hdr {
	char signature[4];
	uint32_t length;
	uint8_t revision;
	uint8_t checksum;
	char oem_id[6];
	char oem_table_id[8];
	uint32_t oem_revision;
	uint32_t creator_id;
	uint32_t creator_revision;
} __attribute__((packed));

typedef struct {
	uint64_t addr;
	uint64_t len;
	uint32_t type;
	uint32_t zero;
} __attribute__((packed)) mb2_mmap_ent_t;

/*
 * ACPI 1.0 FADT through fixed-feature flags (first 116 bytes of FACP body after
 * standard ACPI header — matches Linux early FADT parsing for PM1 + DSDT).
 */
typedef struct {
	struct acpi_sdt_hdr hdr;
	uint32_t firmware_ctrl;
	uint32_t dsdt;
	uint8_t reserved;
	uint8_t preferred_pm_profile;
	uint16_t sci_int;
	uint32_t smi_cmd;
	uint8_t acpi_enable;
	uint8_t acpi_disable;
	uint8_t s4bios_req;
	uint8_t pstate_cnt;
	uint32_t pm1a_evt_blk;
	uint32_t pm1b_evt_blk;
	uint32_t pm1a_cnt_blk;
	uint32_t pm1b_cnt_blk;
	uint32_t pm2_cnt_blk;
	uint32_t pm_tmr_blk;
	uint32_t gpe0_blk;
	uint32_t gpe1_blk;
	uint8_t pm1_evt_len;
	uint8_t pm1_cnt_len;
	uint8_t pm2_cnt_len;
	uint8_t pm_tmr_len;
	uint8_t gpe0_blk_len;
	uint8_t gpe1_blk_len;
	uint8_t gpe1_base;
	uint8_t cst_cnt;
	uint16_t p_lvl2_lat;
	uint16_t p_lvl3_lat;
	uint16_t flush_size;
	uint16_t flush_stride;
	uint8_t duty_offset;
	uint8_t duty_width;
	uint8_t day_alrm;
	uint8_t mon_alrm;
	uint8_t century;
	uint16_t iapc_boot_arch;
	uint8_t reserved2;
	uint32_t flags;
} __attribute__((packed)) acpi_fadt_legacy_t;

static int acpi_sum_ok(const void *tbl, uint32_t len) {
	if (len < sizeof(struct acpi_sdt_hdr))
		return -1;
	const uint8_t *b = (const uint8_t *)tbl;
	uint8_t s = 0;
	for (uint32_t i = 0; i < len; i++)
		s += b[i];
	return s == 0 ? 0 : -1;
}

static const uint8_t *acpi_phys8(uint64_t pa) {
	return (const uint8_t *)(uintptr_t)pa;
}

static int parse_rsdp_at(const uint8_t *p, uint64_t *xsdt_or_rsdt_pa, int *use_xsdt) {
	if (memcmp(p, "RSD PTR ", 8) != 0)
		return -1;
	uint8_t s = 0;
	for (int i = 0; i < 20; i++)
		s += p[i];
	if (s != 0)
		return -1;
	uint8_t rev = p[15];
	if (rev >= 2) {
		uint32_t extlen = *(const uint32_t *)(p + 20);
		if (extlen < 36)
			return -1;
		s = 0;
		for (uint32_t i = 0; i < extlen; i++)
			s += p[i];
		if (s != 0)
			return -1;
		*xsdt_or_rsdt_pa = *(const uint64_t *)(p + 24);
		*use_xsdt = 1;
		return 0;
	}
	*xsdt_or_rsdt_pa = *(const uint32_t *)(p + 16);
	*use_xsdt = 0;
	return 0;
}

static int scan_rsdp_region(uint64_t base, uint64_t len, uint64_t *root_pa, int *use_xsdt) {
	if (len < 20)
		return -1;
	uint64_t max_off = len - 20;
	for (uint64_t off = 0; off <= max_off; off += 16u) {
		const uint8_t *p = acpi_phys8(base + off);
		if (parse_rsdp_at(p, root_pa, use_xsdt) == 0)
			return 0;
	}
	return -1;
}

static int rsdp_find_legacy_rom(uint64_t *xsdt_or_rsdt_pa, int *use_xsdt) {
	uint16_t ebda_seg = *(const uint16_t *)(uintptr_t)0x40Eu;
	if (ebda_seg != 0) {
		uint64_t ebda = (uint64_t)ebda_seg * 16u;
		if (ebda + 1024u <= 0x100000u) {
			if (scan_rsdp_region(ebda, 1024u, xsdt_or_rsdt_pa, use_xsdt) == 0)
				return 0;
		}
	}
	return scan_rsdp_region(0xE0000u, 0x20000u, xsdt_or_rsdt_pa, use_xsdt);
}

static int rsdp_scan_mb2_acpi_mmap(uint64_t multiboot_info_ptr, uint64_t *root_pa, int *use_xsdt) {
	uint8_t *p = (uint8_t *)(uintptr_t)multiboot_info_ptr;
	uint32_t total_size = *(uint32_t *)p;
	if (total_size < 16 || total_size > (64u * 1024u * 1024u))
		return -1;

	uint32_t off = 8;
	while (off + 8 <= total_size) {
		uint32_t tag_type = *(uint32_t *)(p + off);
		uint32_t tag_size = *(uint32_t *)(p + off + 4);
		if (tag_size < 8)
			break;
		if ((uint64_t)off + (uint64_t)tag_size > (uint64_t)total_size)
			break;
		if (tag_type == 0)
			break;

		if (tag_type == 6 && tag_size >= 16) {
			uint32_t entry_size = *(uint32_t *)(p + off + 8);
			if (entry_size >= sizeof(mb2_mmap_ent_t)) {
				uint32_t entries_off = off + 16;
				uint32_t entries_end = off + tag_size;
				for (uint32_t eoff = entries_off; eoff + entry_size <= entries_end; eoff += entry_size) {
					mb2_mmap_ent_t *e = (mb2_mmap_ent_t *)(p + eoff);
					if (e->type != 3u && e->type != 4u)
						continue;
					if (e->len == 0)
						continue;
					if (scan_rsdp_region(e->addr, e->len, root_pa, use_xsdt) == 0)
						return 0;
				}
			}
		}
		off += (tag_size + 7) & ~7u;
	}
	return -1;
}

static int rsdp_from_mb2_acpi_tags(uint64_t multiboot_info_ptr, uint64_t *root_pa, int *use_xsdt) {
	uint8_t *p = (uint8_t *)(uintptr_t)multiboot_info_ptr;
	uint32_t total_size = *(uint32_t *)p;
	if (total_size < 16 || total_size > (64u * 1024u * 1024u))
		return -1;

	uint32_t off = 8;
	while (off + 8 <= total_size) {
		uint32_t tag_type = *(uint32_t *)(p + off);
		uint32_t tag_size = *(uint32_t *)(p + off + 4);
		if (tag_size < 8)
			break;
		if ((uint64_t)off + (uint64_t)tag_size > (uint64_t)total_size)
			break;
		if (tag_type == 0)
			break;

		if ((tag_type == MB2_TAG_ACPI_OLD || tag_type == MB2_TAG_ACPI_NEW) && tag_size >= 8u + 20u) {
			const uint8_t *rp = (const uint8_t *)(p + off + 8);
			if (parse_rsdp_at(rp, root_pa, use_xsdt) == 0)
				return 0;
		}

		off += (tag_size + 7) & ~7u;
	}
	return -1;
}

static int locate_rsdp(uint64_t *root_pa, int *use_xsdt, uint32_t mb_magic, uint64_t mb_info) {
	if (mb_magic == MB2_MAGIC && mb_info != 0) {
		if (rsdp_from_mb2_acpi_tags(mb_info, root_pa, use_xsdt) == 0)
			return 0;
		if (rsdp_scan_mb2_acpi_mmap(mb_info, root_pa, use_xsdt) == 0)
			return 0;
	}
	if (rsdp_find_legacy_rom(root_pa, use_xsdt) == 0)
		return 0;
	return -1;
}

static const struct acpi_sdt_hdr *find_table_sig(uint64_t root_pa, int use_xsdt, const char sig[4]) {
	const struct acpi_sdt_hdr *root = (const struct acpi_sdt_hdr *)acpi_phys8(root_pa);
	if (acpi_sum_ok(root, root->length) != 0)
		return NULL;
	uint32_t hlen = sizeof(struct acpi_sdt_hdr);
	if (root->length < hlen + (use_xsdt ? 8u : 4u))
		return NULL;

	if (use_xsdt) {
		uint32_t nent = (root->length - hlen) / 8u;
		for (uint32_t i = 0; i < nent; i++) {
			uint64_t ent = *(const uint64_t *)(acpi_phys8(root_pa + hlen + i * 8u));
			if (ent == 0)
				continue;
			const struct acpi_sdt_hdr *t = (const struct acpi_sdt_hdr *)acpi_phys8(ent);
			if (memcmp(t->signature, sig, 4) != 0)
				continue;
			if (acpi_sum_ok(t, t->length) != 0)
				continue;
			return t;
		}
	} else {
		uint32_t nent = (root->length - hlen) / 4u;
		for (uint32_t i = 0; i < nent; i++) {
			uint32_t ent = *(const uint32_t *)(acpi_phys8(root_pa + hlen + i * 4u));
			if (ent == 0)
				continue;
			const struct acpi_sdt_hdr *t = (const struct acpi_sdt_hdr *)acpi_phys8((uint64_t)ent);
			if (memcmp(t->signature, sig, 4) != 0)
				continue;
			if (acpi_sum_ok(t, t->length) != 0)
				continue;
			return t;
		}
	}
	return NULL;
}

typedef struct {
	uint16_t pm1a_evt;
	uint16_t pm1a_cnt;
	uint16_t pm1b_cnt;
	uint8_t pm1_evt_len;
	uint8_t pm1_cnt_len;
	uint8_t sci_irq;
	uint32_t smi_cmd;
	uint8_t acpi_enable;
	uint32_t fadt_flags;
	uint8_t slp_typa;
	uint8_t slp_typb;
	int have_s5;
} acpi_powerbtn_hw_t;

static acpi_powerbtn_hw_t g_hw;
static int g_sci_inited;

/* ACPI fixed-feature bits */
#define PM1_STS_PWRBTN (1u << 8)
#define PM1_EN_PWRBTN  (1u << 8)
#define PM1_CNT_SCI_EN (1u << 0)
#define PM1_CNT_SLP_EN (1u << 13)

/*
 * AML: Name(\_S5_, Package(...) { ... constants ... })
 * We scan for the 5-byte name opcode sequence used by most firmware (incl. QEMU/VBox/VMware).
 */
static void acpi_try_parse_s5_from_aml(const uint8_t *aml, uint32_t aml_len) {
	if (!aml || aml_len < 16 || g_hw.have_s5)
		return;

	for (uint32_t i = 0; i + 8 < aml_len; i++) {
		uint32_t body = 0;
		/* NameOp + "_S5_" */
		if (aml[i] == 0x08u && aml[i + 1] == 0x5Fu && aml[i + 2] == 0x53u && aml[i + 3] == 0x35u &&
		    aml[i + 4] == 0x5Fu)
			body = i + 5u;
		/* RootChar '\' + NameSeg "_S5_" */
		else if (aml[i] == 0x5Cu && aml[i + 1] == 0x5Fu && aml[i + 2] == 0x53u && aml[i + 3] == 0x35u &&
			 aml[i + 4] == 0x5Fu)
			body = i + 5u;
		else
			continue;

		uint8_t typa = 0xFF;
		uint8_t typb = 0xFF;
		const uint32_t scan_end = (body + 96u < aml_len) ? (body + 96u) : aml_len;
		for (uint32_t j = body; j + 1u < scan_end; j++) {
			if (aml[j] != 0x0Au)
				continue;
			uint8_t v = aml[j + 1u];
			if (v > 15u)
				continue;
			if (typa == 0xFFu)
				typa = v;
			else if (typb == 0xFFu)
				typb = v;
			else
				break;
		}
		if (typa != 0xFFu) {
			if (typb == 0xFFu)
				typb = typa;
			g_hw.slp_typa = typa;
			g_hw.slp_typb = typb;
			g_hw.have_s5 = 1;
			klogprintf("acpi: parsed _S5_ SLP_TYPa=%u SLP_TYPb=%u\n",
			           (unsigned)g_hw.slp_typa, (unsigned)g_hw.slp_typb);
			return;
		}
	}
}

static void acpi_scan_definition_block(const struct acpi_sdt_hdr *tbl) {
	if (!tbl || tbl->length <= sizeof(struct acpi_sdt_hdr))
		return;
	uint32_t aml_len = tbl->length - (uint32_t)sizeof(struct acpi_sdt_hdr);
	const uint8_t *aml = (const uint8_t *)tbl + sizeof(struct acpi_sdt_hdr);
	acpi_try_parse_s5_from_aml(aml, aml_len);
}

static void acpi_scan_dsdt_ssdt_from_root(uint64_t root_pa, int use_xsdt) {
	const struct acpi_sdt_hdr *root = (const struct acpi_sdt_hdr *)acpi_phys8(root_pa);
	if (acpi_sum_ok(root, root->length) != 0)
		return;
	uint32_t hlen = sizeof(struct acpi_sdt_hdr);
	if (root->length < hlen + (use_xsdt ? 8u : 4u))
		return;

	if (use_xsdt) {
		uint32_t nent = (root->length - hlen) / 8u;
		for (uint32_t i = 0; i < nent; i++) {
			uint64_t ent = *(const uint64_t *)(acpi_phys8(root_pa + hlen + i * 8u));
			if (ent == 0)
				continue;
			const struct acpi_sdt_hdr *t = (const struct acpi_sdt_hdr *)acpi_phys8(ent);
			if (memcmp(t->signature, "DSDT", 4) != 0 && memcmp(t->signature, "SSDT", 4) != 0)
				continue;
			if (acpi_sum_ok(t, t->length) != 0)
				continue;
			acpi_scan_definition_block(t);
			if (g_hw.have_s5)
				return;
		}
	} else {
		uint32_t nent = (root->length - hlen) / 4u;
		for (uint32_t i = 0; i < nent; i++) {
			uint32_t ent = *(const uint32_t *)(acpi_phys8(root_pa + hlen + i * 4u));
			if (ent == 0)
				continue;
			const struct acpi_sdt_hdr *t = (const struct acpi_sdt_hdr *)acpi_phys8((uint64_t)ent);
			if (memcmp(t->signature, "DSDT", 4) != 0 && memcmp(t->signature, "SSDT", 4) != 0)
				continue;
			if (acpi_sum_ok(t, t->length) != 0)
				continue;
			acpi_scan_definition_block(t);
			if (g_hw.have_s5)
				return;
		}
	}
}

static void acpi_sci_isr(cpu_registers_t *regs) {
	(void)regs;
	if (!g_sci_inited || g_hw.pm1a_evt == 0)
		return;

	uint16_t sts = inports(g_hw.pm1a_evt);
	static int once;
	if (sts & (uint16_t)PM1_STS_PWRBTN) {
		if (!once) {
			once = 1;
			uint16_t en = inports((uint16_t)(g_hw.pm1a_evt + 2u));
			klogprintf("acpi: PWRBTN_STS set (pm1_sts=0x%04x pm1_en=0x%04x)\n",
			           (unsigned)sts, (unsigned)en);
			kprintf("\n[acpi] power button (sts=0x%04x en=0x%04x)\n",
			        (unsigned)sts, (unsigned)en);
		}
		outports(g_hw.pm1a_evt, (uint16_t)PM1_STS_PWRBTN);
		power_request_shutdown("ACPI power button");
	}
}

static int acpi_enable_if_needed(const acpi_powerbtn_hw_t *hw) {
	if (!hw || hw->pm1a_cnt == 0)
		return -1;
	uint16_t cnt = inports(hw->pm1a_cnt);
	if (cnt & (uint16_t)PM1_CNT_SCI_EN)
		return 0;
	if (hw->smi_cmd == 0 || hw->acpi_enable == 0)
		return -1;

	outb((unsigned short)hw->smi_cmd, hw->acpi_enable);

	for (int i = 0; i < 2000000; i++) {
		cnt = inports(hw->pm1a_cnt);
		if (cnt & (uint16_t)PM1_CNT_SCI_EN)
			return 0;
#if defined(__GNUC__) || defined(__clang__)
		__asm__ volatile("pause");
#endif
	}
	return -1;
}

void acpi_try_power_off(void) {
	if (g_hw.pm1a_cnt == 0) {
		shutdown_system();
		return;
	}

	if (g_hw.fadt_flags & FADT_HW_REDUCED_ACPI) {
		klogprintf("acpi: HW_REDUCED FADT — falling back to legacy shutdown ports\n");
		shutdown_system();
		return;
	}

	uint8_t typa = g_hw.have_s5 ? g_hw.slp_typa : 5u;
	uint8_t typb = g_hw.have_s5 ? g_hw.slp_typb : typa;

	klogprintf("acpi: S5 PM1 write SLP_TYPa=%u SLP_TYPb=%u pm1a_cnt=0x%x pm1b_cnt=0x%x\n",
	           (unsigned)typa, (unsigned)typb,
	           (unsigned)g_hw.pm1a_cnt, (unsigned)g_hw.pm1b_cnt);
	kprintf("[acpi] S5 shutdown (SLP_TYP %u/%u)\n", (unsigned)typa, (unsigned)typb);

	uint16_t slpa = (uint16_t)((uint16_t)typa << 10);
	uint16_t slpb = (uint16_t)((uint16_t)typb << 10);
	uint16_t slp_en = (uint16_t)PM1_CNT_SLP_EN;

	uint16_t a = inports(g_hw.pm1a_cnt);
	a = (uint16_t)((a & (uint16_t)~0x3C00u) | slpa | slp_en);
	outports(g_hw.pm1a_cnt, a);

	if (g_hw.pm1b_cnt != 0) {
		uint16_t b = inports(g_hw.pm1b_cnt);
		b = (uint16_t)((b & (uint16_t)~0x3C00u) | slpb | slp_en);
		outports(g_hw.pm1b_cnt, b);
	}

	for (;;) {
#if defined(__GNUC__) || defined(__clang__)
		__asm__ volatile("sti; hlt" ::: "memory");
#else
		for (volatile int i = 0; i < 1000000; i++) { }
#endif
	}
}

int acpi_powerbtn_init(uint32_t multiboot_magic, uint64_t multiboot_info) {
	memset(&g_hw, 0, sizeof(g_hw));
	g_sci_inited = 0;

	uint64_t root = 0;
	int xsdt = 0;
	if (locate_rsdp(&root, &xsdt, multiboot_magic, multiboot_info) != 0)
		return -1;

	const struct acpi_sdt_hdr *fadt_hdr = find_table_sig(root, xsdt, "FACP");
	if (!fadt_hdr)
		return -1;
	if (fadt_hdr->length < sizeof(acpi_fadt_legacy_t))
		return -1;

	const acpi_fadt_legacy_t *fadt = (const acpi_fadt_legacy_t *)fadt_hdr;
	if (fadt->pm1a_evt_blk == 0 || fadt->pm1a_cnt_blk == 0 || fadt->sci_int == 0)
		return -1;

	g_hw.pm1a_evt = (uint16_t)(fadt->pm1a_evt_blk & 0xFFFFu);
	g_hw.pm1a_cnt = (uint16_t)(fadt->pm1a_cnt_blk & 0xFFFFu);
	g_hw.pm1b_cnt = (fadt->pm1b_cnt_blk != 0) ? (uint16_t)(fadt->pm1b_cnt_blk & 0xFFFFu) : 0;
	g_hw.pm1_evt_len = fadt->pm1_evt_len;
	g_hw.pm1_cnt_len = fadt->pm1_cnt_len;
	g_hw.sci_irq = (uint8_t)(fadt->sci_int & 0xFFu);
	g_hw.smi_cmd = fadt->smi_cmd;
	g_hw.acpi_enable = fadt->acpi_enable;
	g_hw.fadt_flags = fadt->flags;

	/* DSDT from FADT (32-bit physical); also scan all SSDTs from root. */
	if (fadt->dsdt != 0) {
		const struct acpi_sdt_hdr *dsdt =
		    (const struct acpi_sdt_hdr *)acpi_phys8((uint64_t)fadt->dsdt);
		if (acpi_sum_ok(dsdt, dsdt->length) == 0 && memcmp(dsdt->signature, "DSDT", 4) == 0)
			acpi_scan_definition_block(dsdt);
	}
	acpi_scan_dsdt_ssdt_from_root(root, xsdt);

	if (!g_hw.have_s5)
		klogprintf("acpi: _S5_ not found in AML scan; using SLP_TYP fallback 5 (common on VMs)\n");

	klogprintf("acpi: FADT ok sci_irq=%u pm1a_evt=0x%x pm1a_cnt=0x%x smi_cmd=0x%x acpi_en=0x%x flags=0x%x\n",
	           (unsigned)g_hw.sci_irq,
	           (unsigned)g_hw.pm1a_evt,
	           (unsigned)g_hw.pm1a_cnt,
	           (unsigned)g_hw.smi_cmd,
	           (unsigned)g_hw.acpi_enable,
	           (unsigned)g_hw.fadt_flags);
	kprintf("acpi: FADT ok sci_irq=%u pm1a_evt=0x%x pm1a_cnt=0x%x\n",
	        (unsigned)g_hw.sci_irq, (unsigned)g_hw.pm1a_evt, (unsigned)g_hw.pm1a_cnt);

	if (acpi_enable_if_needed(&g_hw) != 0) {
		klogprintf("acpi: failed to enable SCI (power button disabled; S5 may still work)\n");
		kprintf("acpi: enable SCI failed (S5 only)\n");
		return -1;
	}

	outports(g_hw.pm1a_evt, 0xFFFFu);

	uint16_t en = inports((uint16_t)(g_hw.pm1a_evt + 2u));
	en |= (uint16_t)PM1_EN_PWRBTN;
	outports((uint16_t)(g_hw.pm1a_evt + 2u), en);
	klogprintf("acpi: PM1_EN now 0x%04x\n", (unsigned)en);

	idt_set_handler((uint8_t)(32u + g_hw.sci_irq), acpi_sci_isr);
	pic_unmask_irq(g_hw.sci_irq);

	g_sci_inited = 1;
	klogprintf("acpi: power button enabled on SCI IRQ%u\n", (unsigned)g_hw.sci_irq);
	kprintf("acpi: power button enabled on IRQ%u\n", (unsigned)g_hw.sci_irq);
	return 0;
}
