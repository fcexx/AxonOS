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

/* AHCI minimal probe/registration.
   - Scans PCI devices for class 0x01 / subclass 0x06 / prog_if 0x01 (AHCI)
   - Maps controller MMIO (BAR5) and reads Ports Implemented (PI)
   - For each implemented port reads PxSIG and registers simple disk entry
     so higher-level SATA/ATAPI drivers can attach later.
*/

#define AHCI_REG_CAP    0x00
#define AHCI_REG_GHC    0x04
#define AHCI_REG_PI     0x0C
#define AHCI_PORT_BASE  0x100
#define AHCI_PORT_SIZE  0x80
#define AHCI_PORT_SIG   0x24

/* SATA signatures (common constants) */
#define SATA_SIG_ATA    0x00000101
#define SATA_SIG_ATAPI  0xEB140101
#define SATA_SIG_SEMB   0xC33C0101
#define SATA_SIG_PM     0x96690101

static void ahci_register_simple_disk(int controller_idx, int port, uint32_t sectors_guess, const char *model) {
	disk_ops_t *ops = (disk_ops_t *)kmalloc(sizeof(disk_ops_t));
	if (!ops) return;
	memset(ops, 0, sizeof(*ops));
	char namebuf[32];
	snprintf(namebuf, sizeof(namebuf), "ahci%dp%d", controller_idx, port);
	ops->name = (const char *)kmalloc(strlen(namebuf) + 1);
	if (ops->name) strcpy((char *)ops->name, namebuf);
	ops->init = NULL;
	ops->read = NULL; /* driver will attach proper ops later */
	ops->write = NULL;

	int id = disk_register(ops);
	if (id < 0) {
		kfree((void *)ops->name);
		kfree(ops);
		return;
	}
	/* create device nodes for convenience */
	char devpath[32];
	snprintf(devpath, sizeof(devpath), "/dev/%s", namebuf);
	devfs_create_block_node(devpath, id, sectors_guess);
	klogprintf("AHCI: registered simple disk %s model=\"%s\" size_guess=%uMB\n", namebuf, model ? model : "unknown", sectors_guess / 2048);
}

int ahci_probe_and_register(void) {
	int found = 0;
	pci_device_t *devs = pci_get_devices();
	int count = pci_get_device_count();
	for (int i = 0; i < count; i++) {
		pci_device_t *pdev = &devs[i];
		/* class 0x01 mass storage, subclass 0x06 SATA, prog_if 0x01 AHCI */
		if (pdev->class_code == 0x01 && pdev->subclass == 0x06 && pdev->prog_if == 0x01) {
			/* BAR5 usually holds controller MMIO */
			uint32_t bar = pdev->bar[5];
			if (bar == 0) continue;
			uint64_t phys = (uint64_t)(bar & ~0xFULL);
			void *hba = mmio_map_phys(phys, 4096);
			if (!hba) {
				klogprintf("ahci: failed to map controller at 0x%llx\n", (unsigned long long)phys);
				continue;
			}
			uint32_t pi = mmio_read32(hba, AHCI_REG_PI);
			if (pi == 0) {
				mmio_unmap(hba, 4096);
				continue;
			}
			klogprintf("ahci: controller %02x:%02x.%x mapped at 0x%llx ports_impl=0x%08x\n",
			           pdev->bus, pdev->device, pdev->function, (unsigned long long)phys, pi);
			int controller_idx = found;
			for (int port = 0; port < 32; port++) {
				if (!(pi & (1u << port))) continue;
				uint32_t sig = mmio_read32(hba, AHCI_PORT_BASE + port * AHCI_PORT_SIZE + AHCI_PORT_SIG);
				const char *type = "unknown";
				if (sig == SATA_SIG_ATA) type = "SATA";
				else if (sig == SATA_SIG_ATAPI) type = "ATAPI";
				else if (sig == SATA_SIG_SEMB) type = "SEMB";
				else if (sig == SATA_SIG_PM) type = "PORTMULT";
				else type = "none";
				/* Guess sectors: unknown, set to 0xffffffff to indicate unknown size */
				uint32_t guess_sectors = 0xFFFFFFFFU;
				char model[32];
				snprintf(model, sizeof(model), "%s_sig_0x%08x", type, sig);
				ahci_register_simple_disk(controller_idx, port, guess_sectors, model);
				found++;
			}
			/* keep mapping — mmio_unmap(hba,4096); // keep mapped if driver later needs it */
		}
	}
	return found;
}


