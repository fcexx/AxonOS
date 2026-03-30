#pragma once

#include <stdint.h>
#include <stddef.h>

/* --- SCSI CDB opcodes (SPC-4 / SBC-3) --- */
#define SCSI_TEST_UNIT_READY    0x00
#define SCSI_REQUEST_SENSE     0x03
#define SCSI_INQUIRY           0x12
#define SCSI_READ_CAPACITY_10  0x25
#define SCSI_READ_10           0x28
#define SCSI_WRITE_10          0x2A

/* Direction for execute_command */
#define SCSI_DATA_NONE  0
#define SCSI_DATA_IN    1   /* data from device to host */
#define SCSI_DATA_OUT   2   /* data from host to device */

/* Sense key (byte 2 of fixed format sense) */
#define SCSI_SK_NO_SENSE        0x00
#define SCSI_SK_RECOVERED       0x01
#define SCSI_SK_NOT_READY      0x02
#define SCSI_SK_MEDIUM_ERROR    0x03
#define SCSI_SK_HARDWARE_ERROR  0x04
#define SCSI_SK_ILLEGAL_REQUEST 0x05
#define SCSI_SK_UNIT_ATTENTION  0x06
#define SCSI_SK_DATA_PROTECT    0x07
#define SCSI_SK_ABORTED_COMMAND 0x0B

/* Max CDB length we support */
#define SCSI_CDB_MAX_LEN 16

/* Standard 512-byte sector for block interface */
#define SCSI_BLOCK_SIZE 512

/*
 * scsi_transport_ops_t — интерфейс транспорта (HBA, USB BOT, и т.д.)
 * execute_command: выполнить одну SCSI команду.
 *   priv       — контекст транспорта (HBA, endpoint, и т.д.)
 *   cdb        — SCSI CDB
 *   cdb_len    — длина CDB (6, 10, 12, 16)
 *   data       — буфер для данных (ввод/вывод)
 *   data_len   — размер буфера
 *   direction  — SCSI_DATA_NONE / SCSI_DATA_IN / SCSI_DATA_OUT
 * Возврат: 0 — успех, -1 — ошибка (в т.ч. check condition; детали в sense).
 */
typedef struct scsi_transport_ops {
	int (*execute_command)(void *priv,
	                       const uint8_t *cdb, size_t cdb_len,
	                       void *data, size_t data_len,
	                       int direction);
} scsi_transport_ops_t;

/*
 * scsi_register_lun — зарегистрировать SCSI LUN как блочное устройство.
 * Транспорт вызывает после обнаружения устройства (TEST UNIT READY, READ CAPACITY
 * выполняются внутри). Создаётся disk_ops_t и узлы в devfs (/dev/sdX, партиции).
 *
 * transport_priv — передаётся в ops->execute_command
 * ops          — операции транспорта
 * lun_id       — номер LUN (0..255), для логов и имён
 * Возврат: disk device_id (>=0) или -1 при ошибке.
 */
int scsi_register_lun(void *transport_priv,
                      const scsi_transport_ops_t *ops,
                      int lun_id);

/*
 * scsi_init — инициализация подсистемы SCSI (подготовка таблицы LUN).
 * Вызвать до ata_dma_init(), чтобы ATA/AHCI могли регистрировать диски в SCSI.
 */
void scsi_init(void);

/*
 * scsi_register_disk_as_lun — зарегистрировать уже зарегистрированный в disk слой диск
 * как SCSI LUN (для /proc/scsi/scsi и единого представления как в Linux).
 * Узел /dev/sdX уже создан ATA/AHCI; дубликат не создаётся.
 */
int scsi_register_disk_as_lun(int disk_id, uint32_t sectors,
                              const char *vendor, const char *product, const char *revision);

/*
 * Информация о зарегистрированных SCSI дисках (для /proc/scsi/scsi и т.п.).
 * scsi_lun_count — число LUN.
 * scsi_lun_get_info — по индексу 0..count-1 заполняет vendor, product, revision,
 * out_sectors, out_disk_id; out_dev_letter = 'a'+disk_id для /dev/sdX (или '?').
 */
int scsi_lun_count(void);
int scsi_lun_get_info(int index, char *vendor, size_t vlen, char *product, size_t plen,
                      char *revision, size_t rlen, uint32_t *out_sectors, int *out_disk_id, char *out_dev_letter);
