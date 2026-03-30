#include <smp_madt.h>
#include <stdint.h>
#include <string.h>

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

/* Multiboot2 mmap entry (tag type 6) */
typedef struct {
	uint64_t addr;
	uint64_t len;
	uint32_t type;
	uint32_t zero;
} __attribute__((packed)) mb2_mmap_ent_t;

#define MADT_ENTRIES_OFF 44u
#define MB2_MAGIC 0x36d76289u
/* GRUB multiboot2.h: ACPI RSDP embedded in info tag payload */
#define MB2_TAG_ACPI_OLD 14u
#define MB2_TAG_ACPI_NEW 15u

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
					/* ACPI reclaimable / ACPI NVS — VMware places RSDP+XSDT+MADT here */
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

/* Inline ACPI 1.0/2.0+ RSDP copy from bootloader (most reliable on VMware/GRUB). */
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

static const struct acpi_sdt_hdr *find_apic_table(uint64_t root_pa, int use_xsdt) {
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
			const struct acpi_sdt_hdr *t =
			    (const struct acpi_sdt_hdr *)acpi_phys8(ent);
			if (memcmp(t->signature, "APIC", 4) != 0)
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
			const struct acpi_sdt_hdr *t =
			    (const struct acpi_sdt_hdr *)acpi_phys8((uint64_t)ent);
			if (memcmp(t->signature, "APIC", 4) != 0)
				continue;
			if (acpi_sum_ok(t, t->length) != 0)
				continue;
			return t;
		}
	}
	return NULL;
}

static void sort_u8(uint8_t *a, int n) {
	for (int i = 0; i < n; i++) {
		for (int j = i + 1; j < n; j++) {
			if (a[j] < a[i]) {
				uint8_t t = a[i];
				a[i] = a[j];
				a[j] = t;
			}
		}
	}
}

int smp_madt_enumerate(uint8_t bsp_apic, int *out_n, uint8_t out_map[SMP_MAX_CPUS], uint32_t mb_magic,
		       uint64_t mb_info) {
	uint64_t root = 0;
	int xsdt = 0;
	if (!out_n || !out_map)
		return -1;
	if (locate_rsdp(&root, &xsdt, mb_magic, mb_info) != 0)
		return -1;
	const struct acpi_sdt_hdr *madt = find_apic_table(root, xsdt);
	if (!madt)
		return -1;
	if (madt->length < MADT_ENTRIES_OFF + 2u)
		return -1;

	uint8_t raw[SMP_MAX_CPUS + 8];
	int nr = 0;

	const uint8_t *base = (const uint8_t *)madt;
	const uint8_t *p = base + MADT_ENTRIES_OFF;
	const uint8_t *end = base + madt->length;

	while (p + 2 <= end) {
		uint8_t typ = p[0];
		uint8_t len = p[1];
		if (len < 2 || p + len > end)
			break;

		if (typ == 0 && len >= 8u) {
			uint8_t apic_id = p[3];
			uint32_t fl = *(const uint32_t *)(p + 4);
			if ((fl & 1u) && nr < (int)sizeof(raw)) {
				int dup = 0;
				for (int k = 0; k < nr; k++) {
					if (raw[k] == apic_id) {
						dup = 1;
						break;
					}
				}
				if (!dup)
					raw[nr++] = apic_id;
			}
		} else if (typ == 9 && len >= 16u) {
			uint32_t x2 = *(const uint32_t *)(p + 4);
			uint32_t fl = *(const uint32_t *)(p + 8);
			if ((fl & 1u) && x2 < 256u && nr < (int)sizeof(raw)) {
				uint8_t apic_id = (uint8_t)x2;
				int dup = 0;
				for (int k = 0; k < nr; k++) {
					if (raw[k] == apic_id) {
						dup = 1;
						break;
					}
				}
				if (!dup)
					raw[nr++] = apic_id;
			}
		}
		p += len;
	}

	if (nr < 1)
		return -1;
	if (nr > SMP_MAX_CPUS)
		return -1;

	sort_u8(raw, nr);

	uint8_t try_bsp[2];
	int ntry = 0;
	try_bsp[ntry++] = bsp_apic;
	uint32_t eax, ebx, ecx, edx;
	asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1), "c"(0));
	uint8_t bsp_cpuid = (uint8_t)((ebx >> 24) & 0xffu);
	if (bsp_cpuid != bsp_apic)
		try_bsp[ntry++] = bsp_cpuid;

	int bi = -1;
	uint8_t chosen = bsp_apic;
	for (int t = 0; t < ntry && bi < 0; t++) {
		for (int i = 0; i < nr; i++) {
			if (raw[i] == try_bsp[t]) {
				bi = i;
				chosen = try_bsp[t];
				break;
			}
		}
	}
	if (bi < 0)
		return -1;

	out_map[0] = chosen;
	int o = 1;
	for (int i = 0; i < nr && o < SMP_MAX_CPUS; i++) {
		if (raw[i] == chosen)
			continue;
		out_map[o++] = raw[i];
	}
	*out_n = o;
	if (*out_n != nr)
		return -1;
	return 0;
}
