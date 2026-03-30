#pragma once

#include <stdint.h>

/* Probe and register one ATAPI device at given IDE position.
   Returns 0 on success, -1 if not an ATAPI device or registration failed. */
int atapi_try_register_device(uint16_t io_base, uint16_t ctrl_base, int is_slave);

/* Acknowledge pending ATA/ATAPI IRQ on registered ATAPI devices. */
void atapi_irq_ack_all(void);