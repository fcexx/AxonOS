/*
 * drv/disk/ahci.c
 * SATA AHCI Driver
 * Author: Auto-generated
 */

#include <ahci.h>
#include <disk.h>
#include <pci.h>
#include <mmio.h>
#include <heap.h>
#include <string.h>
#include <vga.h>
#include <devfs.h>
#include <axonos.h>

#define AHCI_MAX_CONTROLLERS      4
#define AHCI_CMD_LIST_SIZE       (32 * sizeof(ahci_cmd_list_entry_t))
#define AHCI_FIS_SIZE             256
#define AHCI_ALIGNMENT            4096

static ahci_controller_t ahci_controllers[AHCI_MAX_CONTROLLERS];
static int ahci_controller_count = 0;
static int ahci_device_count = 0;
/* When non-zero, attempt IDENTIFY on ports even if SSTS.DET != 3 (force probe).
   Useful for virtual machines where the firmware exposes disk via SATA but DET
   bits are not set. Use with caution (out-of-spec). */
static int ahci_force_probe = 1;

/* Helper: wait for port to not be busy */
static int ahci_wait_clear(volatile void *port_base, uint32_t reg, uint32_t mask, int timeout_ms) {
    int loops = timeout_ms * 1000;
    while (loops--) {
        uint32_t val = mmio_read32(port_base, reg);
        if ((val & mask) == 0) return 0;
        /* small delay */
        for (volatile int i = 0; i < 100; i++);
    }
    return -1;
}

/* Helper: wait for port to set bit */
static int ahci_wait_set(volatile void *port_base, uint32_t reg, uint32_t mask, int timeout_ms) {
    int loops = timeout_ms * 1000;
    while (loops--) {
        uint32_t val = mmio_read32(port_base, reg);
        if ((val & mask) != 0) return 0;
        for (volatile int i = 0; i < 100; i++);
    }
    return -1;
}

/* Stop command engine */
static void ahci_port_stop(ahci_port_t *port) {
    volatile void *base = port->port_base;
    
    /* Clear FRE and ST */
    uint32_t cmd = mmio_read32(base, AHCI_PxCMD);
    cmd &= ~AHCI_PxCMD_ST;
    mmio_write32(base, AHCI_PxCMD, cmd);
    
    /* Wait for CR to clear */
    ahci_wait_clear(base, AHCI_PxCMD, AHCI_PxCMD_CR, 500);
    
    /* Clear FRE */
    cmd = mmio_read32(base, AHCI_PxCMD);
    cmd &= ~AHCI_PxCMD_FRE;
    mmio_write32(base, AHCI_PxCMD, cmd);
    
    /* Wait for FR to clear */
    ahci_wait_clear(base, AHCI_PxCMD, AHCI_PxCMD_FR, 500);
}

/* Start command engine */
static int ahci_port_start(ahci_port_t *port) {
    volatile void *base = port->port_base;
    
    /* Set FRE */
    uint32_t cmd = mmio_read32(base, AHCI_PxCMD);
    cmd |= AHCI_PxCMD_FRE;
    mmio_write32(base, AHCI_PxCMD, cmd);
    
    /* Wait for FR to set */
    if (ahci_wait_set(base, AHCI_PxCMD, AHCI_PxCMD_FR, 500) != 0) {
        return -1;
    }
    
    /* Set ST */
    cmd = mmio_read32(base, AHCI_PxCMD);
    cmd |= AHCI_PxCMD_ST;
    mmio_write32(base, AHCI_PxCMD, cmd);
    
    return 0;
}

/* Reset port */
static int ahci_port_reset(ahci_port_t *port) {
    volatile void *base = port->port_base;
    
    /* Stop command engine */
    ahci_port_stop(port);
    
    /* Clear error status */
    mmio_write32(base, AHCI_PxSERR, 0xFFFFFFFF);
    
    /* Clear interrupt status */
    mmio_write32(base, AHCI_PxIS, 0xFFFFFFFF);
    
    /* Issue COMRESET - set DET to 1 (perform interface initialization) */
    uint32_t sctl = mmio_read32(base, AHCI_PxSCTL);
    sctl &= ~0xF;
    sctl |= 1; /* DET = 1: perform interface initialization */
    mmio_write32(base, AHCI_PxSCTL, sctl);
    
    /* Wait for reset to propagate */
    for (volatile int i = 0; i < 100000; i++);
    
    /* Clear COMRESET - set DET to 0 (no action) */
    sctl &= ~0xF;
    sctl |= 0; /* DET = 0: no action */
    mmio_write32(base, AHCI_PxSCTL, sctl);
    
    /* Wait longer for device to be ready and establish communication */
    for (volatile int i = 0; i < 1000000; i++);
    
    /* Check status */
    uint32_t ssts = mmio_read32(base, AHCI_PxSSTS);
    uint32_t det = (ssts >> AHCI_PxSSTS_DET_SHIFT) & AHCI_PxSSTS_DET_MASK;
    klogprintf("ahci: Port %d: After COMRESET, DET=%d\n", port->port_num, det);
    
    return 0;
}

/* Check if device is present on port */
static int ahci_port_check_device(ahci_port_t *port) {
    volatile void *base = port->port_base;
    uint32_t ssts = mmio_read32(base, AHCI_PxSSTS);
    uint32_t det = (ssts >> AHCI_PxSSTS_DET_SHIFT) & AHCI_PxSSTS_DET_MASK;
    uint32_t ipm = (ssts >> AHCI_PxSSTS_IPM_SHIFT) & AHCI_PxSSTS_IPM_MASK;
    uint32_t spd = (ssts >> AHCI_PxSSTS_SPD_SHIFT) & AHCI_PxSSTS_SPD_MASK;
    
    /* DET=3 means device present and communication established */
    if (det == AHCI_PxSSTS_DET_PRESENT) {
        klogprintf("ahci: Port %d: Device present (DET=3, IPM=%d, SPD=%d)\n", 
                  port->port_num, ipm, spd);
        return 1;
    }
    
    /* DET=1 or DET=2 might be transitional states - wait a bit */
    if (det == 1 || det == 2) {
        klogprintf("ahci: Port %d: Device in transitional state (DET=%d), waiting...\n", 
                  port->port_num, det);
        for (volatile int i = 0; i < 1000000; i++);
        ssts = mmio_read32(base, AHCI_PxSSTS);
        det = (ssts >> AHCI_PxSSTS_DET_SHIFT) & AHCI_PxSSTS_DET_MASK;
        if (det == AHCI_PxSSTS_DET_PRESENT) {
            klogprintf("ahci: Port %d: Device now present after wait\n", port->port_num);
            return 1;
        }
    }
    
    return 0;
}

/* Execute command on port */
static int ahci_port_execute(ahci_port_t *port, uint8_t slot, ahci_cmd_table_t *cmd_table, 
                             void *buffer, size_t buffer_size) {
    volatile void *base = port->port_base;
    
    /* Wait for port to not be busy */
    uint32_t tfd_before = mmio_read32(base, AHCI_PxTFD);
    if (ahci_wait_clear(base, AHCI_PxTFD, AHCI_PxTFD_STS_BSY | AHCI_PxTFD_STS_DRQ, 500) != 0) {
        uint32_t tfd_after = mmio_read32(base, AHCI_PxTFD);
        klogprintf("ahci: Port %d: Port busy timeout, TFD before=0x%x after=0x%x\n",
                  port->port_num, tfd_before, tfd_after);
        return -1;
    }
    
    /* Clear interrupt status */
    mmio_write32(base, AHCI_PxIS, 0xFFFFFFFF);
    
    /* Setup command list entry */
    ahci_cmd_list_entry_t *cmd_list = (ahci_cmd_list_entry_t *)port->cmd_list;
    ahci_cmd_list_entry_t *entry = &cmd_list[slot];
    
    memset(entry, 0, sizeof(ahci_cmd_list_entry_t));
    
    /* Calculate command table physical address */
    uint32_t cmd_table_phys = port->cmd_list_phys + AHCI_CMD_LIST_SIZE + (slot * AHCI_CMD_TABLE_SIZE);
    entry->ctba = (uint64_t)cmd_table_phys;
    entry->prdtl = (buffer && buffer_size > 0) ? 1 : 0; /* One PRD entry if buffer provided */
    entry->flags = (5 << AHCI_CMD_FLAG_CFL_SHIFT); /* 5 DWords in CFIS */
    
    klogprintf("ahci: Port %d: CMD list entry: CTBA=0x%llx PRDTL=%d flags=0x%x\n",
              port->port_num, (unsigned long long)entry->ctba, entry->prdtl, entry->flags);
    
    /* Copy command table */
    void *cmd_table_virt = (void *)((uintptr_t)port->cmd_list + AHCI_CMD_LIST_SIZE + (slot * AHCI_CMD_TABLE_SIZE));
    memcpy(cmd_table_virt, cmd_table, sizeof(ahci_cmd_table_t));
    
    /* Log FIS command being sent (from local copy) */
    ahci_fis_h2d_t *fis = (ahci_fis_h2d_t *)cmd_table->cfis;
    klogprintf("ahci: Port %d: FIS: type=0x%x cmd=0x%x device=0x%x\n",
              port->port_num, fis->fis_type, fis->command, fis->device);
    /* Also dump first bytes of the command table actually written to memory for debugging */
    {
        uint8_t *p = (uint8_t *)cmd_table_virt;
        char dump[64];
        int dp = 0;
        for (int i = 0; i < 32 && dp < (int)sizeof(dump)-3; i++) {
            int n = snprintf(dump + dp, sizeof(dump) - dp, "%02x ", p[i]);
            if (n <= 0) break;
            dp += n;
        }
        dump[dp] = '\\0';
        klogprintf("ahci: Port %d: CMD table dump: %s\n", port->port_num, dump);
    }
    
    /* Setup PRD if buffer provided */
    if (buffer && buffer_size > 0) {
        ahci_cmd_table_t *table = (ahci_cmd_table_t *)((uintptr_t)port->cmd_list + 
                                                        AHCI_CMD_LIST_SIZE + 
                                                        (slot * AHCI_CMD_TABLE_SIZE));
        /* Use physical address (identity mapped for addresses < 4GB) */
        uintptr_t buffer_phys = (uintptr_t)buffer;
        if (buffer_phys >= 0x100000000ULL) {
            klogprintf("ahci: buffer address >= 4GB not supported\n");
            return -1;
        }
        table->prdt[0].dba = (uint64_t)buffer_phys;
        table->prdt[0].dbc = (uint32_t)(buffer_size - 1); /* 0-based, so 0 = 1 byte */
        table->prdt[0].reserved = 0;
        klogprintf("ahci: Port %d: PRD: DBA=0x%llx DBC=%u\n",
                  port->port_num, (unsigned long long)table->prdt[0].dba, table->prdt[0].dbc);
    }
    
    /* Check port is ready - CMD.ST must be set */
    uint32_t cmd_reg = mmio_read32(base, AHCI_PxCMD);
    if (!(cmd_reg & AHCI_PxCMD_ST)) {
        klogprintf("ahci: Port %d: ERROR: Command engine not started (CMD=0x%x)\n", 
                  port->port_num, cmd_reg);
        return -1;
    }
    
    /* Check port is not busy */
    uint32_t tfd_check = mmio_read32(base, AHCI_PxTFD);
    if (tfd_check & (AHCI_PxTFD_STS_BSY | AHCI_PxTFD_STS_DRQ)) {
        klogprintf("ahci: Port %d: ERROR: Port still busy (TFD=0x%x)\n", 
                  port->port_num, tfd_check);
        return -1;
    }
    
    /* Issue command - set bit in CI register to start command */
    uint32_t ci_before = mmio_read32(base, AHCI_PxCI);
    klogprintf("ahci: Port %d: Before command, CI=0x%x CMD=0x%x TFD=0x%x\n", 
              port->port_num, ci_before, cmd_reg, tfd_check);
    
    /* Check if slot is already in use */
    if (ci_before & (1 << slot)) {
        klogprintf("ahci: Port %d: WARNING: Slot %d already in use (CI=0x%x)\n",
                  port->port_num, slot, ci_before);
        return -1;
    }
    
    /* Set bit corresponding to slot (OR operation, not overwrite) */
    uint32_t ci_issue = ci_before | (1 << slot);
    
    /* Memory barrier before MMIO write */
    asm volatile("mfence" ::: "memory");
    
    klogprintf("ahci: Port %d: About to write CI=0x%x...\n", port->port_num, ci_issue);
    mmio_write32(base, AHCI_PxCI, ci_issue);
    
    /* Memory barrier after MMIO write */
    asm volatile("mfence" ::: "memory");
    
    klogprintf("ahci: Port %d: CI write completed\n", port->port_num);
    
    /* Small delay to ensure write is processed */
    for (volatile int i = 0; i < 1000; i++);
    
    /* Read back to verify */
    uint32_t ci_after = mmio_read32(base, AHCI_PxCI);
    klogprintf("ahci: Port %d: Command issued, CI written=0x%x CI read=0x%x\n", 
              port->port_num, ci_issue, ci_after);
    
    /* Check if command was accepted */
    if ((ci_after & (1 << slot)) == 0) {
        klogprintf("ahci: Port %d: ERROR: Command bit not set after write! Port may be busy.\n", port->port_num);
        return -1;
    }
    
    /* Wait for command completion */
    int timeout = 5000; /* 5 seconds */
    int check_count = 0;
	uint32_t ci;
    while (timeout--) {
        ci = mmio_read32(base, AHCI_PxCI);
        if ((ci & (1 << slot)) == 0) {
            /* Command completed, check status */
            uint32_t tfd = mmio_read32(base, AHCI_PxTFD);
            uint32_t is = mmio_read32(base, AHCI_PxIS);
            klogprintf("ahci: Port %d: Command completed, TFD=0x%x IS=0x%x\n", 
                      port->port_num, tfd, is);
            
            if (tfd & AHCI_PxTFD_STS_ERR) {
                uint32_t serr = mmio_read32(base, AHCI_PxSERR);
                klogprintf("ahci: Port %d: Command error, TFD=0x%x SERR=0x%x\n",
                          port->port_num, tfd, serr);
                return -1;
            }
            klogprintf("ahci: Port %d: Command successful\n", port->port_num);
            return 0;
        }
        
        /* Log progress every 1000 iterations */
        if (++check_count % 1000 == 0) {
            uint32_t tfd = mmio_read32(base, AHCI_PxTFD);
            klogprintf("ahci: Port %d: Waiting for command, CI=0x%x TFD=0x%x (timeout=%d)\n",
                      port->port_num, ci, tfd, timeout);
        }
        
        for (volatile int i = 0; i < 1000; i++);
    }
    
    /* Timeout - get final status */
    ci = mmio_read32(base, AHCI_PxCI);
    uint32_t tfd = mmio_read32(base, AHCI_PxTFD);
    uint32_t is = mmio_read32(base, AHCI_PxIS);
    uint32_t serr = mmio_read32(base, AHCI_PxSERR);
    klogprintf("ahci: Port %d: Command timeout! CI=0x%x TFD=0x%x IS=0x%x SERR=0x%x\n",
              port->port_num, ci, tfd, is, serr);
    return -1;
}

/* Identify device */
static int ahci_port_identify(ahci_port_t *port) {
    volatile void *base = port->port_base;
    
    /* Allocate buffer for IDENTIFY data */
    uint16_t *identify_buf = (uint16_t *)kmalloc(512);
    if (!identify_buf) return -1;
    memset(identify_buf, 0, 512);
    
    /* Build command table */
    ahci_cmd_table_t cmd_table;
    memset(&cmd_table, 0, sizeof(cmd_table));
    
    /* Build FIS H2D */
    ahci_fis_h2d_t *fis = (ahci_fis_h2d_t *)cmd_table.cfis;
    fis->fis_type = FIS_TYPE_REG_H2D;
    fis->pmport_c = 0x80; /* Command bit set */
    fis->command = ATA_CMD_IDENTIFY;
    fis->device = 0;
    fis->count_low = 0;
    fis->count_high = 0;
    fis->lba_low = 0;
    fis->lba_mid = 0;
    fis->lba_high = 0;
    fis->control = 0;
    
    /* Execute command */
    klogprintf("ahci: Port %d: Executing IDENTIFY command...\n", port->port_num);
    int r = ahci_port_execute(port, 0, &cmd_table, identify_buf, 512);
    if (r != 0) {
        klogprintf("ahci: Port %d: IDENTIFY command execution failed\n", port->port_num);
        kfree(identify_buf);
        return -1;
    }
    klogprintf("ahci: Port %d: IDENTIFY command completed successfully\n", port->port_num);
    
    /* Extract model string */
    for (int i = 0; i < 20; i++) {
        uint16_t w = identify_buf[27 + i];
        port->model[i * 2] = (char)(w >> 8);
        port->model[i * 2 + 1] = (char)(w & 0xFF);
    }
    port->model[40] = '\0';
    
    /* Trim trailing spaces */
    int len = strlen(port->model);
    while (len > 0 && port->model[len - 1] == ' ') {
        port->model[--len] = '\0';
    }
    
    /* Get sector count */
    uint64_t sectors = 0;
    /* Try 48-bit LBA first (words 100-103) */
    sectors = (uint64_t)identify_buf[100] |
              ((uint64_t)identify_buf[101] << 16) |
              ((uint64_t)identify_buf[102] << 32) |
              ((uint64_t)identify_buf[103] << 48);
    
    if (sectors == 0) {
        /* Fallback to 28-bit LBA (words 60-61) */
        sectors = (uint32_t)identify_buf[60] | ((uint32_t)identify_buf[61] << 16);
    }
    
    port->sectors = sectors;
    
    kfree(identify_buf);
    return 0;
}

/* Initialize port */
static int ahci_port_init(ahci_port_t *port) {
    volatile void *base = port->port_base;
    
    /* Check initial device status */
    uint32_t ssts = mmio_read32(base, AHCI_PxSSTS);
    uint32_t det = (ssts >> AHCI_PxSSTS_DET_SHIFT) & AHCI_PxSSTS_DET_MASK;
    uint32_t sig = mmio_read32(base, AHCI_PxSIG);
    
    klogprintf("ahci: Port %d init: SSTS=0x%x DET=%d SIG=0x%x\n", port->port_num, ssts, det, sig);
    
    /* If device not present, try to reset and check again */
    if (det != AHCI_PxSSTS_DET_PRESENT) {
        klogprintf("ahci: Port %d: Device not present (DET=%d), attempting reset...\n", port->port_num, det);
        
        /* Reset port */
        ahci_port_reset(port);
        
        /* Wait for device to stabilize */
        for (volatile int i = 0; i < 500000; i++);
        
        /* Check again */
        ssts = mmio_read32(base, AHCI_PxSSTS);
        det = (ssts >> AHCI_PxSSTS_DET_SHIFT) & AHCI_PxSSTS_DET_MASK;
        klogprintf("ahci: Port %d: After reset SSTS=0x%x DET=%d\n", port->port_num, ssts, det);
    }
    
    /* Check if device is present */
    port->device_present = ahci_port_check_device(port);
    if (!port->device_present) {
        if (!ahci_force_probe) {
            klogprintf("ahci: Port %d: No device present after reset\n", port->port_num);
            return -1;
        } else {
            klogprintf("ahci: Port %d: No DET=3 but force-probing enabled, will attempt IDENTIFY\n", port->port_num);
            /* continue and try IDENTIFY even without DET==3 */
        }
    }
    
    /* Check signature - should be 0x00000101 for ATA device */
    sig = mmio_read32(base, AHCI_PxSIG);
    if (sig != 0x00000101) {
        klogprintf("ahci: Port %d: Unexpected signature 0x%x (expected 0x00000101 for ATA)\n", port->port_num, sig);
        /* Continue anyway - might be ATAPI or other device */
    }
    
    /* Allocate command list (32 entries, 32 bytes each = 1024 bytes)
       Must be 1KB aligned according to AHCI spec */
    size_t total_size = AHCI_CMD_LIST_SIZE + (32 * AHCI_CMD_TABLE_SIZE);
    void *raw_alloc = kmalloc(total_size + 1024); /* Allocate extra for alignment */
    if (!raw_alloc) {
        return -1;
    }
    
    /* Align to 1KB boundary */
    uintptr_t addr = (uintptr_t)raw_alloc;
    uintptr_t aligned = (addr + 1023) & ~1023ULL;
    port->cmd_list = (void *)aligned;
    port->cmd_list_orig = raw_alloc; /* Save original pointer for freeing */
    
    if (aligned != addr) {
        klogprintf("ahci: Port %d: Command list realigned from %p to %p\n",
                  port->port_num, (void *)addr, (void *)aligned);
    }
    
    memset(port->cmd_list, 0, total_size);
    port->cmd_list_phys = (uint32_t)(uintptr_t)port->cmd_list; /* Identity mapped */
    
    /* Verify alignment */
    if ((port->cmd_list_phys & 0x3FF) != 0) {
        klogprintf("ahci: Port %d: WARNING: Command list not 1KB aligned (phys=0x%x)\n",
                  port->port_num, port->cmd_list_phys);
    } else {
        klogprintf("ahci: Port %d: Command list aligned at 0x%x\n",
                  port->port_num, port->cmd_list_phys);
    }
    
    /* Allocate FIS receive area (256 bytes) */
    port->fis = kmalloc(AHCI_FIS_SIZE);
    if (!port->fis) {
        if (port->cmd_list_orig) {
            kfree(port->cmd_list_orig);
        } else {
            kfree(port->cmd_list);
        }
        return -1;
    }
    memset(port->fis, 0, AHCI_FIS_SIZE);
    port->fis_phys = (uint32_t)(uintptr_t)port->fis; /* Identity mapped */
    
    /* Setup command list base */
    mmio_write32(base, AHCI_PxCLB, port->cmd_list_phys & 0xFFFFFFFF);
    mmio_write32(base, AHCI_PxCLBU, 0);
    
    /* Setup FIS base */
    mmio_write32(base, AHCI_PxFB, port->fis_phys & 0xFFFFFFFF);
    mmio_write32(base, AHCI_PxFBU, 0);
    
    /* Enable interrupts */
    mmio_write32(base, AHCI_PxIE, 0xFFFFFFFF);
    
    /* Start command engine */
    klogprintf("ahci: Port %d: Starting command engine...\n", port->port_num);
    if (ahci_port_start(port) != 0) {
        klogprintf("ahci: Port %d: Failed to start command engine\n", port->port_num);
        kfree(port->fis);
        if (port->cmd_list_orig) {
            kfree(port->cmd_list_orig);
        } else {
            kfree(port->cmd_list);
        }
        return -1;
    }
    klogprintf("ahci: Port %d: Command engine started\n", port->port_num);
    
    /* Wait for device to be ready */
    klogprintf("ahci: Port %d: Waiting for device to be ready...\n", port->port_num);
    if (ahci_wait_clear(base, AHCI_PxTFD, AHCI_PxTFD_STS_BSY, 1000) != 0) {
        uint32_t tfd = mmio_read32(base, AHCI_PxTFD);
        klogprintf("ahci: Port %d: Device not ready, TFD=0x%x\n", port->port_num, tfd);
        ahci_port_stop(port);
        kfree(port->fis);
        if (port->cmd_list_orig) {
            kfree(port->cmd_list_orig);
        } else {
            kfree(port->cmd_list);
        }
        return -1;
    }
    klogprintf("ahci: Port %d: Device is ready\n", port->port_num);
    
    /* Identify device */
    klogprintf("ahci: Port %d: Sending IDENTIFY command...\n", port->port_num);
    if (ahci_port_identify(port) != 0) {
        klogprintf("ahci: Port %d: IDENTIFY failed\n", port->port_num);
        ahci_port_stop(port);
        kfree(port->fis);
        if (port->cmd_list_orig) {
            kfree(port->cmd_list_orig);
        } else {
            kfree(port->cmd_list);
        }
        return -1;
    }
    klogprintf("ahci: Port %d: IDENTIFY successful, model=\"%s\", sectors=%llu\n",
              port->port_num, port->model, (unsigned long long)port->sectors);
    
    /* Mark device as present when IDENTIFY succeeded (even if DET wasn't 3) */
    port->device_present = 1;
    
    port->initialized = 1;
    return 0;
}

/* Read sectors */
static int ahci_read_sectors(int device_id, uint32_t lba, void *buf, uint32_t sectors) {
    if (device_id < 0 || device_id >= ahci_device_count) return -1;
    
    /* Find port for this device */
    ahci_port_t *port = NULL;
    int port_device_id = 0;
    for (int c = 0; c < ahci_controller_count; c++) {
        for (int p = 0; p < ahci_controllers[c].num_ports; p++) {
            if (ahci_controllers[c].ports[p].initialized && 
                ahci_controllers[c].ports[p].device_present) {
                if (port_device_id == device_id) {
                    port = &ahci_controllers[c].ports[p];
                    break;
                }
                port_device_id++;
            }
        }
        if (port) break;
    }
    
    if (!port) return -1;
    
    volatile void *base = port->port_base;
    uint32_t bytes = sectors * 512;
    uint8_t *buffer = (uint8_t *)buf;
    uint64_t current_lba = lba;
    uint32_t remaining = sectors;
    
    while (remaining > 0) {
        uint16_t count = (remaining > 65535) ? 65535 : (uint16_t)remaining;
        
        /* Wait for port to be ready */
        if (ahci_wait_clear(base, AHCI_PxTFD, AHCI_PxTFD_STS_BSY | AHCI_PxTFD_STS_DRQ, 500) != 0) {
            return -1;
        }
        
        /* Build command table */
        ahci_cmd_table_t cmd_table;
        memset(&cmd_table, 0, sizeof(cmd_table));
        
        /* Build FIS H2D */
        ahci_fis_h2d_t *fis = (ahci_fis_h2d_t *)cmd_table.cfis;
        fis->fis_type = FIS_TYPE_REG_H2D;
        fis->pmport_c = 0x80;
        fis->command = ATA_CMD_READ_DMA_EXT;
        fis->device = 0x40; /* LBA mode */
        fis->lba_low = (uint8_t)(current_lba & 0xFF);
        fis->lba_mid = (uint8_t)((current_lba >> 8) & 0xFF);
        fis->lba_high = (uint8_t)((current_lba >> 16) & 0xFF);
        fis->device |= (uint8_t)((current_lba >> 24) & 0x0F);
        fis->lba_low_ext = (uint8_t)((current_lba >> 24) & 0xF0) | (uint8_t)((current_lba >> 32) & 0x0F);
        fis->lba_mid_ext = (uint8_t)((current_lba >> 32) & 0xF0) | (uint8_t)((current_lba >> 40) & 0x0F);
        fis->lba_high_ext = (uint8_t)((current_lba >> 40) & 0xF0);
        fis->count_low = (uint8_t)(count & 0xFF);
        fis->count_high = (uint8_t)((count >> 8) & 0xFF);
        fis->control = 0;
        
        /* Execute command */
        uint32_t transfer_size = count * 512;
        if (ahci_port_execute(port, 0, &cmd_table, buffer, transfer_size) != 0) {
            return -1;
        }
        
        buffer += transfer_size;
        current_lba += count;
        remaining -= count;
    }
    
    return 0;
}

/* Write sectors */
static int ahci_write_sectors(int device_id, uint32_t lba, const void *buf, uint32_t sectors) {
    if (device_id < 0 || device_id >= ahci_device_count) return -1;
    
    /* Find port for this device */
    ahci_port_t *port = NULL;
    int port_device_id = 0;
    for (int c = 0; c < ahci_controller_count; c++) {
        for (int p = 0; p < ahci_controllers[c].num_ports; p++) {
            if (ahci_controllers[c].ports[p].initialized && 
                ahci_controllers[c].ports[p].device_present) {
                if (port_device_id == device_id) {
                    port = &ahci_controllers[c].ports[p];
                    break;
                }
                port_device_id++;
            }
        }
        if (port) break;
    }
    
    if (!port) return -1;
    
    volatile void *base = port->port_base;
    const uint8_t *buffer = (const uint8_t *)buf;
    uint64_t current_lba = lba;
    uint32_t remaining = sectors;
    
    while (remaining > 0) {
        uint16_t count = (remaining > 65535) ? 65535 : (uint16_t)remaining;
        
        /* Wait for port to be ready */
        if (ahci_wait_clear(base, AHCI_PxTFD, AHCI_PxTFD_STS_BSY | AHCI_PxTFD_STS_DRQ, 500) != 0) {
            return -1;
        }
        
        /* Build command table */
        ahci_cmd_table_t cmd_table;
        memset(&cmd_table, 0, sizeof(cmd_table));
        
        /* Build FIS H2D */
        ahci_fis_h2d_t *fis = (ahci_fis_h2d_t *)cmd_table.cfis;
        fis->fis_type = FIS_TYPE_REG_H2D;
        fis->pmport_c = 0x80;
        fis->command = ATA_CMD_WRITE_DMA_EXT;
        fis->device = 0x40; /* LBA mode */
        fis->lba_low = (uint8_t)(current_lba & 0xFF);
        fis->lba_mid = (uint8_t)((current_lba >> 8) & 0xFF);
        fis->lba_high = (uint8_t)((current_lba >> 16) & 0xFF);
        fis->device |= (uint8_t)((current_lba >> 24) & 0x0F);
        fis->lba_low_ext = (uint8_t)((current_lba >> 24) & 0xF0) | (uint8_t)((current_lba >> 32) & 0x0F);
        fis->lba_mid_ext = (uint8_t)((current_lba >> 32) & 0xF0) | (uint8_t)((current_lba >> 40) & 0x0F);
        fis->lba_high_ext = (uint8_t)((current_lba >> 40) & 0xF0);
        fis->count_low = (uint8_t)(count & 0xFF);
        fis->count_high = (uint8_t)((count >> 8) & 0xFF);
        fis->control = 0;
        
        /* Set write flag */
        ahci_cmd_list_entry_t *cmd_list = (ahci_cmd_list_entry_t *)port->cmd_list;
        cmd_list[0].flags |= AHCI_CMD_FLAG_WRITE;
        
        /* Execute command */
        uint32_t transfer_size = count * 512;
        if (ahci_port_execute(port, 0, &cmd_table, (void *)buffer, transfer_size) != 0) {
            cmd_list[0].flags &= ~AHCI_CMD_FLAG_WRITE;
            return -1;
        }
        
        cmd_list[0].flags &= ~AHCI_CMD_FLAG_WRITE;
        buffer += transfer_size;
        current_lba += count;
        remaining -= count;
    }
    
    return 0;
}

/* Initialize AHCI controller */
static int ahci_controller_init(ahci_controller_t *ctrl) {
    pci_device_t *pci = ctrl->pci_dev;
    
    /* Get AHCI base address - try BAR5 first, then BAR0 */
    uint32_t base = 0;
    uint32_t bar5 = pci->bar[5];
    if ((bar5 & 1) == 0 && bar5 != 0) {
        /* Memory space, not I/O */
        base = bar5 & ~0xF;
        klogprintf("ahci: Using BAR5: 0x%x\n", base);
    } else {
        /* Try BAR0 */
        uint32_t bar0 = pci->bar[0];
        if ((bar0 & 1) == 0 && bar0 != 0) {
            base = bar0 & ~0xF;
            klogprintf("ahci: Using BAR0: 0x%x\n", base);
        } else {
            klogprintf("ahci: No valid memory BAR found (BAR0=0x%x BAR5=0x%x)\n", bar0, bar5);
            return -1;
        }
    }
    
    ctrl->mmio_base_phys = base;
    ctrl->mmio_base = (volatile void *)(uintptr_t)base; /* Identity mapped */
    
    /* Enable bus mastering and memory space */
    uint32_t command = pci_config_read_dword(pci->bus, pci->device, pci->function, 0x04);
    command |= 0x05; /* Bus master + memory space */
    pci_config_write_dword(pci->bus, pci->device, pci->function, 0x04, command);
    
    /* Read capabilities */
    ctrl->cap = mmio_read32(ctrl->mmio_base, AHCI_CAP);
    ctrl->cap2 = mmio_read32(ctrl->mmio_base, AHCI_CAP2);
    ctrl->ports_implemented = mmio_read32(ctrl->mmio_base, AHCI_PI);
    
    /* Count implemented ports */
    ctrl->num_ports = 0;
    for (int i = 0; i < 32; i++) {
        if (ctrl->ports_implemented & (1 << i)) {
            ctrl->num_ports++;
        }
    }
    
    klogprintf("ahci: Controller found: cap=0x%x ports_impl=0x%x num_ports=%d\n",
              ctrl->cap, ctrl->ports_implemented, ctrl->num_ports);
    
    /* Enable AHCI */
    uint32_t ghc = mmio_read32(ctrl->mmio_base, AHCI_GHC);
    if (!(ghc & AHCI_GHC_AE)) {
        ghc |= AHCI_GHC_AE;
        mmio_write32(ctrl->mmio_base, AHCI_GHC, ghc);
        
        /* Wait for AE to be set */
        int timeout = 1000;
        while (timeout--) {
            ghc = mmio_read32(ctrl->mmio_base, AHCI_GHC);
            if (ghc & AHCI_GHC_AE) break;
            for (volatile int i = 0; i < 1000; i++);
        }
        
        if (!(ghc & AHCI_GHC_AE)) {
            klogprintf("ahci: Failed to enable AHCI\n");
            return -1;
        }
    }
    
    /* Initialize ports */
    int device_id = ahci_device_count;
    for (int i = 0; i < 32; i++) {
        if (!(ctrl->ports_implemented & (1 << i))) continue;
        
        ahci_port_t *port = &ctrl->ports[i];
        port->port_num = i;
        port->port_base = (volatile void *)((char *)ctrl->mmio_base + AHCI_PORT_BASE + (i * AHCI_PORT_SIZE));
        port->initialized = 0;
        port->device_present = 0;
        port->cmd_list_orig = NULL;
        
        /* Check port status before initialization */
        volatile void *base = port->port_base;
        uint32_t ssts = mmio_read32(base, AHCI_PxSSTS);
        uint32_t det = (ssts >> AHCI_PxSSTS_DET_SHIFT) & AHCI_PxSSTS_DET_MASK;
        uint32_t sig = mmio_read32(base, AHCI_PxSIG);
        uint32_t cmd = mmio_read32(base, AHCI_PxCMD);
        
        klogprintf("ahci: Port %d: SSTS=0x%x DET=%d SIG=0x%x CMD=0x%x\n", i, ssts, det, sig, cmd);
        
        /* Try to initialize port */
        int init_result = ahci_port_init(port);
        if (init_result == 0) {
            /* Register device */
            disk_ops_t *ops = (disk_ops_t *)kmalloc(sizeof(disk_ops_t));
            if (!ops) continue;
            
            memset(ops, 0, sizeof(*ops));
            char namebuf[32];
            snprintf(namebuf, sizeof(namebuf), "ahci_port%d", i);
            ops->name = (const char *)kmalloc(strlen(namebuf) + 1);
            if (ops->name) strcpy((char *)ops->name, namebuf);
            ops->init = NULL;
            ops->read = ahci_read_sectors;
            ops->write = ahci_write_sectors;
            
            int id = disk_register(ops);
            if (id < 0) {
                klogprintf("ahci: failed to register device %s\n", namebuf);
                kfree((void *)ops->name);
                kfree(ops);
                continue;
            }
            
            /* Create /dev/sdX node (sda, sdb, sdc, etc.) */
            if (ahci_device_count < 26) {
                char devpath[32];
                snprintf(devpath, sizeof(devpath), "/dev/sd%c", 'a' + ahci_device_count);
                devfs_create_block_node(devpath, id, (uint32_t)port->sectors);
            } else {
                /* Fallback for devices beyond 'z' */
                char devpath[32];
                snprintf(devpath, sizeof(devpath), "/dev/sd%d", ahci_device_count);
                devfs_create_block_node(devpath, id, (uint32_t)port->sectors);
            }
            
            uint32_t size_mb = (uint32_t)(port->sectors / 2048);
            klogprintf("ahci: Port %d: \"%s\" size: %u MB sectors: %llu\n",
                      i, port->model, size_mb, (unsigned long long)port->sectors);
            
            ahci_device_count++;
        } else {
            klogprintf("ahci: Port %d: Initialization failed\n", i);
        }
    }
    
    ctrl->num_devices = ahci_device_count - device_id;
    return 0;
}

/* Initialize AHCI subsystem */
int ahci_init(void) {
    int device_count = pci_get_device_count();
    pci_device_t *devices = pci_get_devices();
    
    klogprintf("ahci: Scanning for AHCI controllers...\n");
    
    ahci_controller_count = 0;
    ahci_device_count = 0;
    
    for (int i = 0; i < device_count && ahci_controller_count < AHCI_MAX_CONTROLLERS; i++) {
        pci_device_t *pci = &devices[i];
        
        /* Check for AHCI controller: class 0x01, subclass 0x06, prog_if 0x01 */
        if (pci->class_code == PCI_CLASS_STORAGE &&
            pci->subclass == PCI_SUBCLASS_SATA &&
            pci->prog_if == PCI_PROGIF_AHCI) {
            
            klogprintf("ahci: Found AHCI controller at %02x:%02x.%d\n",
                      pci->bus, pci->device, pci->function);
            
            ahci_controller_t *ctrl = &ahci_controllers[ahci_controller_count];
            memset(ctrl, 0, sizeof(ahci_controller_t));
            ctrl->pci_dev = pci;
            
            if (ahci_controller_init(ctrl) == 0) {
                ahci_controller_count++;
            } else {
                klogprintf("ahci: Failed to initialize controller\n");
            }
        }
    }
    
    if (ahci_controller_count == 0) {
        klogprintf("ahci: No AHCI controllers found\n");
        return -1;
    }
    
    klogprintf("ahci: Initialized %d controller(s), %d device(s)\n",
              ahci_controller_count, ahci_device_count);
    
    return 0;
}

/* Cleanup AHCI subsystem */
void ahci_cleanup(void) {
    for (int c = 0; c < ahci_controller_count; c++) {
        ahci_controller_t *ctrl = &ahci_controllers[c];
        for (int p = 0; p < ctrl->num_ports; p++) {
            ahci_port_t *port = &ctrl->ports[p];
            if (port->initialized) {
                ahci_port_stop(port);
                if (port->fis) kfree(port->fis);
                if (port->cmd_list_orig) kfree(port->cmd_list_orig);
                else if (port->cmd_list) kfree(port->cmd_list);
            }
        }
    }
    ahci_controller_count = 0;
    ahci_device_count = 0;
}

