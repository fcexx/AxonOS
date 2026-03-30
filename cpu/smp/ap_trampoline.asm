; Raw binary at physical/virtual SMP_TRAMPOLINE_PHYS (0x10000; keep in sync with inc/smp.h).
; Mailbox at 0x9000 — must match struct smp_mailbox in smp.c
; Offsets: +8 cr3, +16 stack_top, +24 entry, +32 lgdt 6 bytes (lim u16, base u32), +40 saved_cr4 (u64)

%define TRAMP_BASE 0x10000
%define MBX 0x9000
%define DIAG_RM   0x5000
%define DIAG_LM   0x5004
%define DIAG_PM32 0x5008

ORG TRAMP_BASE
BITS 16

ap_trampoline_bin_start:
    cli
    xor ax, ax
    mov ds, ax
    o32 mov dword [DIAG_RM], 0x31505341
    mov es, ax
    mov ss, ax
    mov sp, 0x7E00

    ; Real mode default address size is 16-bit: [pm_gdt_desc] truncates to low 16 bits of EA.
    ; At TRAMP_BASE 0x10000 that points at 0x0080 (IVT/BDA), not the real descriptor — #GP before prot32.
    o32 a32 lgdt [pm_gdt_desc]

    mov eax, cr0
    or al, 1
    mov cr0, eax

    ; 66 EA: far jmp imm32:imm16 (32-bit offset + CS). NASM o32 jmp 0x08:(...) truncates wrongly at ORG > 0x8000.
    db 0x66, 0xEA
    dd (prot32 - ap_trampoline_bin_start + TRAMP_BASE)
    dw 0x08

BITS 32
prot32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x7E00

    mov dword [DIAG_PM32], 0xDEAD0032

    ; Intel / OSDev bring-up order: CR4.PAE first, then CR3 (PML4 phys), then EFER.LME, then CR0.PG.
    ; In legacy 32-bit protected mode REX is not valid — use 32-bit mov (PML4 must be below 4 GiB).
    mov eax, [MBX + 40]
    mov cr4, eax

    mov eax, [MBX + 8]
    mov cr3, eax

    ; LME + NXE must match BSP: with NXE=0, PTE bit 63 set by kernel is reserved -> #PF/triple fault.
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8) | (1 << 11)
    wrmsr

    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax

    lgdt [MBX + 32]

    ; Far jump to 64-bit CS: retf pops EIP then CS — push segment first, offset last (on stack top).
    push word 0x08
    push dword (long64 - ap_trampoline_bin_start + TRAMP_BASE)
    retf

BITS 64
long64:
    ; In long mode loading SS with the null selector causes #GP(0). Use kernel data 0x10.
    mov eax, 0x10
    mov ds, eax
    mov es, eax
    mov fs, eax
    mov gs, eax
    mov ss, eax

    mov eax, 0xDEAD0044
    mov ecx, DIAG_LM
    mov dword [rcx], eax

    mov rax, [MBX + 16]
    mov rsp, rax

    mov rax, [MBX + 24]
    jmp rax

pm_gdt_desc:
    dw pm_gdt_end - pm_gdt_start - 1
    dd pm_gdt_start

pm_gdt_start:
    dq 0
    dq 0x00CF9A000000FFFF
    dq 0x00CF92000000FFFF
pm_gdt_end:

ap_trampoline_bin_end:
