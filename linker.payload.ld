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

    .bss : {
        *(.bss)
    }

    _end = .; PROVIDE(end = .);
}
