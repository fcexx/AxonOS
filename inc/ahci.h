#pragma once

#include <stdint.h>
#include <stddef.h>
#include <pci.h>

/* AHCI PCI class/subclass/prog_if */
#define PCI_CLASS_STORAGE        0x01
#define PCI_SUBCLASS_SATA        0x06
#define PCI_PROGIF_AHCI          0x01

/* AHCI Register offsets */
#define AHCI_CAP                 0x00
#define AHCI_GHC                  0x04
#define AHCI_IS                   0x08
#define AHCI_PI                   0x0C
#define AHCI_VS                   0x10
#define AHCI_CCC_CTL              0x14
#define AHCI_CCC_PORTS            0x18
#define AHCI_EM_LOC               0x1C
#define AHCI_EM_CTL               0x20
#define AHCI_CAP2                 0x24
#define AHCI_BOHC                 0x28

/* Port registers base offset */
#define AHCI_PORT_BASE            0x100
#define AHCI_PORT_SIZE            0x80

/* Port register offsets */
#define AHCI_PxCLB                0x00
#define AHCI_PxCLBU               0x04
#define AHCI_PxFB                 0x08
#define AHCI_PxFBU                0x0C
#define AHCI_PxIS                 0x10
#define AHCI_PxIE                 0x14
#define AHCI_PxCMD                0x18
#define AHCI_PxTFD                0x20
#define AHCI_PxSIG                0x24
#define AHCI_PxSSTS               0x28
#define AHCI_PxSCTL               0x2C
#define AHCI_PxSERR               0x30
#define AHCI_PxSACT               0x34
#define AHCI_PxCI                 0x38
#define AHCI_PxSNTF               0x3C
#define AHCI_PxFBS                0x40
#define AHCI_PxDEVSLP             0x44
#define AHCI_PxVS                 0x70

/* AHCI GHC bits */
#define AHCI_GHC_AE               (1 << 31)
#define AHCI_GHC_IE               (1 << 1)
#define AHCI_GHC_HR               (1 << 0)

/* AHCI CAP bits */
#define AHCI_CAP_S64A             (1 << 31)
#define AHCI_CAP_SNCQ             (1 << 30)
#define AHCI_CAP_SSNTF            (1 << 29)
#define AHCI_CAP_SMPS             (1 << 28)
#define AHCI_CAP_SSS              (1 << 27)
#define AHCI_CAP_SALP             (1 << 26)
#define AHCI_CAP_SAL              (1 << 25)
#define AHCI_CAP_SCLO             (1 << 24)
#define AHCI_CAP_ISS_SHIFT        20
#define AHCI_CAP_ISS_MASK         0xF
#define AHCI_CAP_SNZO             (1 << 19)
#define AHCI_CAP_SAM              (1 << 18)
#define AHCI_CAP_SPM              (1 << 17)
#define AHCI_CAP_PMD              (1 << 15)
#define AHCI_CAP_SSC              (1 << 14)
#define AHCI_CAP_PSC              (1 << 13)
#define AHCI_CAP_NCS_SHIFT        8
#define AHCI_CAP_NCS_MASK         0x1F
#define AHCI_CAP_CCCS              (1 << 7)
#define AHCI_CAP_EMS              (1 << 6)
#define AHCI_CAP_SXS              (1 << 5)
#define AHCI_CAP_NP_SHIFT         0
#define AHCI_CAP_NP_MASK          0x1F

/* Port CMD bits */
#define AHCI_PxCMD_ST             (1 << 0)
#define AHCI_PxCMD_SUD            (1 << 1)
#define AHCI_PxCMD_POD            (1 << 2)
#define AHCI_PxCMD_CLO            (1 << 3)
#define AHCI_PxCMD_FRE             (1 << 4)
#define AHCI_PxCMD_FR             (1 << 14)
#define AHCI_PxCMD_CR             (1 << 15)
#define AHCI_PxCMD_CPD            (1 << 20)
#define AHCI_PxCMD_ESP            (1 << 21)
#define AHCI_PxCMD_ICC_SHIFT      28
#define AHCI_PxCMD_ICC_MASK       0xF

/* Port TFD bits */
#define AHCI_PxTFD_STS_BSY        (1 << 7)
#define AHCI_PxTFD_STS_DRQ        (1 << 3)
#define AHCI_PxTFD_STS_ERR        (1 << 0)
#define AHCI_PxTFD_ERR_MASK       0xFF00

/* Port SSTS bits */
#define AHCI_PxSSTS_DET_SHIFT     0
#define AHCI_PxSSTS_DET_MASK      0xF
#define AHCI_PxSSTS_DET_NO_DEVICE 0x0
#define AHCI_PxSSTS_DET_PRESENT   0x3
#define AHCI_PxSSTS_IPM_SHIFT     8
#define AHCI_PxSSTS_IPM_MASK      0xF
#define AHCI_PxSSTS_SPD_SHIFT    12
#define AHCI_PxSSTS_SPD_MASK      0xF

/* Port IS bits */
#define AHCI_PxIS_DHRS            (1 << 0)
#define AHCI_PxIS_PSS             (1 << 1)
#define AHCI_PxIS_DSS             (1 << 2)
#define AHCI_PxIS_SDS             (1 << 3)
#define AHCI_PxIS_UFS             (1 << 4)
#define AHCI_PxIS_DPS             (1 << 5)
#define AHCI_PxIS_PCS             (1 << 6)
#define AHCI_PxIS_DMPS            (1 << 7)
#define AHCI_PxIS_PRCS            (1 << 22)
#define AHCI_PxIS_IPMS            (1 << 23)
#define AHCI_PxIS_OFCS            (1 << 26)
#define AHCI_PxIS_INFS            (1 << 27)
#define AHCI_PxIS_IFS             (1 << 28)
#define AHCI_PxIS_HBDS            (1 << 29)
#define AHCI_PxIS_HBFS            (1 << 30)
#define AHCI_PxIS_TFES            (1 << 30)

/* FIS Types */
#define FIS_TYPE_REG_H2D          0x27
#define FIS_TYPE_REG_D2H          0x34
#define FIS_TYPE_DMA_ACTIVATE      0x39
#define FIS_TYPE_DMA_SETUP        0x41
#define FIS_TYPE_DATA             0x46
#define FIS_TYPE_BIST             0x58
#define FIS_TYPE_PIO_SETUP        0x5F
#define FIS_TYPE_DEV_BITS         0xA1

/* ATA Commands */
#define ATA_CMD_IDENTIFY          0xEC
#define ATA_CMD_READ_DMA_EXT      0x25
#define ATA_CMD_WRITE_DMA_EXT     0x35
#define ATA_CMD_READ_DMA           0xC8
#define ATA_CMD_WRITE_DMA         0xCA

/* Command List Entry flags */
#define AHCI_CMD_FLAG_CFL_SHIFT   0
#define AHCI_CMD_FLAG_CFL_MASK    0x1F
#define AHCI_CMD_FLAG_ATAPI       (1 << 5)
#define AHCI_CMD_FLAG_WRITE       (1 << 6)
#define AHCI_CMD_FLAG_PREFETCH    (1 << 7)
#define AHCI_CMD_FLAG_RESET       (1 << 8)
#define AHCI_CMD_FLAG_BIST        (1 << 9)
#define AHCI_CMD_FLAG_CLR_BUSY    (1 << 10)
#define AHCI_CMD_FLAG_RCS         (1 << 11)
#define AHCI_CMD_FLAG_PMP_SHIFT   12
#define AHCI_CMD_FLAG_PMP_MASK    0xF

/* Command List Entry - 32 bytes */
typedef struct {
    uint16_t flags;
    uint16_t prdtl;              /* PRD table length */
    uint32_t prdbc;              /* PRD byte count */
    uint64_t ctba;               /* Command table base address */
    uint32_t reserved[4];
} __attribute__((packed)) ahci_cmd_list_entry_t;

/* Physical Region Descriptor - 16 bytes */
typedef struct {
    uint64_t dba;                /* Data base address */
    uint32_t reserved;
    uint32_t dbc;                /* Data byte count (0-based, so 0 = 1 byte) */
} __attribute__((packed)) ahci_prd_t;

/* Command Table - 256 bytes */
#define AHCI_CMD_TABLE_SIZE       256
#define AHCI_PRDT_MAX_ENTRIES     ((AHCI_CMD_TABLE_SIZE - 0x80) / sizeof(ahci_prd_t))

typedef struct {
    uint8_t cfis[64];            /* Command FIS */
    uint8_t acmd[16];            /* ATAPI command (if ATAPI) */
    uint8_t reserved[48];
    ahci_prd_t prdt[AHCI_PRDT_MAX_ENTRIES];
} __attribute__((packed)) ahci_cmd_table_t;

/* FIS Register H2D - 20 bytes */
typedef struct {
    uint8_t fis_type;            /* FIS_TYPE_REG_H2D */
    uint8_t pmport_c;            /* Port multiplier port + command flag */
    uint8_t command;
    uint8_t feature_low;
    uint8_t lba_low;
    uint8_t lba_mid;
    uint8_t lba_high;
    uint8_t device;
    uint8_t lba_low_ext;
    uint8_t lba_mid_ext;
    uint8_t lba_high_ext;
    uint8_t feature_high;
    uint8_t count_low;
    uint8_t count_high;
    uint8_t icc;
    uint8_t control;
    uint8_t reserved[4];
} __attribute__((packed)) ahci_fis_h2d_t;

/* FIS Register D2H - 20 bytes */
typedef struct {
    uint8_t fis_type;            /* FIS_TYPE_REG_D2H */
    uint8_t pmport_i;            /* Port multiplier port + interrupt */
    uint8_t status;
    uint8_t error;
    uint8_t lba_low;
    uint8_t lba_mid;
    uint8_t lba_high;
    uint8_t device;
    uint8_t lba_low_ext;
    uint8_t lba_mid_ext;
    uint8_t lba_high_ext;
    uint8_t reserved1;
    uint8_t count_low;
    uint8_t count_high;
    uint8_t reserved2[2];
    uint8_t reserved3[4];
} __attribute__((packed)) ahci_fis_d2h_t;

/* AHCI Port structure */
typedef struct {
    uint8_t port_num;
    volatile void *port_base;    /* MMIO base for this port */
    void *cmd_list;              /* Command list (physical, aligned) */
    void *cmd_list_orig;         /* Original allocation pointer for freeing */
    void *fis;                   /* FIS receive area (physical) */
    uint32_t cmd_list_phys;
    uint32_t fis_phys;
    int device_present;
    uint64_t sectors;            /* Total sectors */
    char model[41];              /* Device model string */
    int initialized;
} ahci_port_t;

/* AHCI Controller structure */
typedef struct {
    pci_device_t *pci_dev;
    volatile void *mmio_base;    /* MMIO base address */
    uint32_t mmio_base_phys;
    uint32_t cap;                /* CAP register */
    uint32_t cap2;               /* CAP2 register */
    uint32_t ports_implemented;  /* PI register */
    int num_ports;
    ahci_port_t ports[32];       /* Max 32 ports */
    int num_devices;
} ahci_controller_t;

/* Public functions */
int ahci_init(void);
void ahci_cleanup(void);

