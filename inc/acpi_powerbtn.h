#pragma once

#include <stdint.h>

/*
 * Minimal ACPI Fixed-Feature power button handling:
 * - parses RSDP -> (X)SDT to locate FADT ("FACP")
 * - enables ACPI (SCI) if required
 * - installs SCI interrupt handler
 * - on PWRBTN_STS: clears status and requests graceful shutdown
 */
int acpi_powerbtn_init(uint32_t multiboot_magic, uint64_t multiboot_info);

/* ACPI S5 soft-off via PM1_CNT (SLP_TYP + SLP_EN); falls back to shutdown_system() if no FADT PM1. */
void acpi_try_power_off(void);

