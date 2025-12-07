#ifndef RTL8139_H
#define RTL8139_H

#include <stdint.h>
#include <stdbool.h>

// Регистры RTL8139 (смещения от базового порта)
#define RTL8139_CMD          0x37
#define RTL8139_IMR          0x3C
#define RTL8139_ISR          0x3E
#define RTL8139_TCR          0x40
#define RTL8139_RCR          0x44
#define RTL8139_CONFIG1      0x52
#define RTL8139_MPC          0x4C

// MAC адрес
#define RTL8139_MAC0         0x00  // MAC 0
#define RTL8139_MAC1         0x01  // MAC 1
#define RTL8139_MAC2         0x02  // MAC 2
#define RTL8139_MAC3         0x03  // MAC 3
#define RTL8139_MAC4         0x04  // MAC 4
#define RTL8139_MAC5         0x05  // MAC 5

// Buffer descriptors
#define RTL8139_RBSTART      0x30  // Receive Buffer Start
#define RTL8139_TSAD0        0x20  // Transmit Start Address 0
#define RTL8139_TSD0         0x10  // Transmit Status 0

// Команды
#define CMD_RX_ENABLE        (1 << 3)
#define CMD_TX_ENABLE        (1 << 2)
#define CMD_RST              (1 << 4)

// Статус прерываний
#define ISR_RX_OK            (1 << 0)
#define ISR_TX_OK            (1 << 2)
#define ISR_RX_ERR           (1 << 1)
#define ISR_TX_ERR           (1 << 3)

// Receive Configuration Register биты
#define RCR_AAP              (1 << 0)   // Accept All Packets
#define RCR_APM              (1 << 1)   // Accept Physical Match
#define RCR_AM               (1 << 2)   // Accept Multicast
#define RCR_AB               (1 << 3)   // Accept Broadcast
#define RCR_WRAP             (1 << 7)   // Wrap
#define RCR_MAX_DMA_UNLIMITED (7 << 8)  // No RX DMA limit

// Размеры буферов
#define RX_BUFFER_SIZE       8192
#define TX_BUFFER_SIZE       1536
#define NUM_TX_BUFFERS       4

// ==================== СТРУКТУРЫ ====================

// Структура драйвера
struct rtl8139_device {
    uint16_t io_base;       // Базовый I/O порт (0xC000)
    uint8_t mac[6];
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
    
    // Буферы
    void* rx_buffer;
    uint32_t rx_buffer_phys;
    uint32_t rx_current;
    
    bool initialized;
};

int rtl8139_init(uint8_t bus, uint8_t slot, uint8_t function);
void rtl8139_test(void);
int rtl8139_command(int argc, char** argv);

void rtl8139_send_packet(const uint8_t* data, uint32_t length);
uint32_t rtl8139_receive_packet(uint8_t* buffer, uint32_t max_len);
void rtl8139_get_mac(uint8_t mac[6]);

void rtl8139_dump_registers(void);

extern struct rtl8139_device rtl8139;

#endif // RTL8139_H