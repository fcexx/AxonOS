OUTPUT_FORMAT("elf64-x86-64")
ENTRY(kernel_main)

SECTIONS
{
    /* Fixed mailbox for AP trampoline (identity-mapped); see smp.c */
    . = 0x9000;
    .smp_mailbox : AT(0x9000) { KEEP(*(.smp_mailbox)) }

    . = 0x100000;

    .text : {
        *(.text)
    }

    .rodata : {
        *(.rodata)
    }

    .data : {
        *(.data)
    }

    /* Must include COMMON and .bss.* or _end sits before real BSS end; RAM past _end
     * still belongs to the kernel and will overwrite the low initrd module (GRUB ~0x103000). */
    .bss : ALIGN(16) {
        *(.bss .bss.*)
        *(COMMON)
    }

    . = ALIGN(16);
    _end = .; PROVIDE(end = .);
}
