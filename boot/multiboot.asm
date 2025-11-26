section .multiboot2
align 8
mb2_start:
        dd 0xe85250d6
        dd 0
        dd mb2_end - mb2_start
        dd 0x100000000 - (0xe85250d6 + 0 + (mb2_end - mb2_start))

        align 8
        dw 0
        dw 0 
        dd 20
        dd 0
        dd 0
        dd 0

        align 8
        dw 0
        dw 0
        dd 8
mb2_end:

section .bss
align 16
stack_bottom:
        resb 16384
stack_top:

align 8
global multiboot_magic_saved
multiboot_magic_saved:
        resq 1
global multiboot_info_saved
multiboot_info_saved:
        resq 1
; page tables in BSS (aligned to 4096)
align 4096
global page_table_l4
page_table_l4:
        resb 4096
global page_table_l3
page_table_l3:
        resb 4096
global page_table_l3_fb
page_table_l3_fb:
        resb 4096
global page_table_pd0
page_table_pd0:
        resb 4096
global page_table_pd1
page_table_pd1:
        resb 4096
global page_table_pd2
page_table_pd2:
        resb 4096
global page_table_pd3
page_table_pd3:
        resb 4096

section .text
global _start
extern kernel_main
bits 32
_start:
        mov esp, stack_top

        push ebx
        push eax

        mov edi, boot_msg_start
        call print_vga

        call check_cpuid
        call check_long_mode

        pop eax
        pop ebx
        mov dword [multiboot_magic_saved], eax
        mov dword [multiboot_magic_saved + 4], 0
        mov dword [multiboot_info_saved], ebx
        mov dword [multiboot_info_saved + 4], 0

        mov edi, boot_msg_before_pt
        call print_vga
        cli
        call setup_page_tables
        mov edi, boot_msg_after_pt
        call print_vga
        mov edi, boot_msg_before_enable
        call print_vga
        call enable_paging
        mov edi, boot_msg_after_enable
        call print_vga

        lea         eax, [tmp_gdt_ptr]
        lgdt        [eax]

        jmp 0x08:long_mode_start

        cli
        hlt

check_cpuid:
        pushfd
        pop eax
        mov ecx, eax
        xor eax, 1 << 21
        push eax
        popfd
        pushfd
        pop eax
        push ecx
        popfd
        cmp eax, ecx
        je .no_cpuid
        ret
.no_cpuid:
        mov al, "1"
        jmp error

check_long_mode:
        mov eax, 0x80000000
        cpuid
        cmp eax, 0x80000001
        jb .no_long_mode
        mov eax, 0x80000001
        cpuid
        test edx, 1 << 29
        jz .no_long_mode
        ret
.no_long_mode:
        mov al, "2"
        jmp error

setup_page_tables:
        ; Build simple identity mapping for first 4 GiB using 2 MiB pages
        ; Layout: PML4 -> PDPT -> 4 PDs (each 512 entries of 2MiB => 1GiB per PD)

        ; zero PML4, PDPT and PDs
        mov edi, page_table_l4
        xor eax, eax
        mov ecx, 1024
        rep stosd

        mov edi, page_table_l3
        xor eax, eax
        mov ecx, 1024
        rep stosd

        mov edi, page_table_pd0
        xor eax, eax
        mov ecx, 1024
        rep stosd

        mov edi, page_table_pd1
        xor eax, eax
        mov ecx, 1024
        rep stosd

        mov edi, page_table_pd2
        xor eax, eax
        mov ecx, 1024
        rep stosd

        mov edi, page_table_pd3
        xor eax, eax
        mov ecx, 1024
        rep stosd

        ; PML4[0] -> PDPT
        mov eax, page_table_l3
        or eax, 0x3          ; present + rw
        mov dword [page_table_l4], eax
        mov dword [page_table_l4 + 4], 0

        ; PDPT entries -> PDs
        mov eax, page_table_pd0
        or eax, 0x3
        mov dword [page_table_l3 + 0*8], eax
        mov dword [page_table_l3 + 0*8 + 4], 0

        mov eax, page_table_pd1
        or eax, 0x3
        mov dword [page_table_l3 + 1*8], eax
        mov dword [page_table_l3 + 1*8 + 4], 0

        mov eax, page_table_pd2
        or eax, 0x3
        mov dword [page_table_l3 + 2*8], eax
        mov dword [page_table_l3 + 2*8 + 4], 0

        mov eax, page_table_pd3
        or eax, 0x3
        mov dword [page_table_l3 + 3*8], eax
        mov dword [page_table_l3 + 3*8 + 4], 0

        ; Fill PDs: each entry maps 2MiB (PS bit = 1 in PDE)
        ; PD0: pages 0..511 -> 0..1GiB
        xor ecx, ecx
        mov ebx, 0
.pd0_loop:
        mov eax, ebx
        add eax, ecx
        shl eax, 21           ; *2MiB
        or eax, 0x83          ; present + rw + PS
        mov dword [page_table_pd0 + ecx*8], eax
        mov dword [page_table_pd0 + ecx*8 + 4], 0
        inc ecx
        cmp ecx, 512
        jne .pd0_loop

        ; PD1: pages 512..1023 -> 1GiB..2GiB
        xor ecx, ecx
        mov ebx, 512
.pd1_loop:
        mov eax, ebx
        add eax, ecx
        shl eax, 21
        or eax, 0x83
        mov dword [page_table_pd1 + ecx*8], eax
        mov dword [page_table_pd1 + ecx*8 + 4], 0
        inc ecx
        cmp ecx, 512
        jne .pd1_loop

        ; PD2: pages 1024..1535 -> 2GiB..3GiB
        xor ecx, ecx
        mov ebx, 1024
.pd2_loop:
        mov eax, ebx
        add eax, ecx
        shl eax, 21
        or eax, 0x83
        mov dword [page_table_pd2 + ecx*8], eax
        mov dword [page_table_pd2 + ecx*8 + 4], 0
        inc ecx
        cmp ecx, 512
        jne .pd2_loop

        ; PD3: pages 1536..2047 -> 3GiB..4GiB
        xor ecx, ecx
        mov ebx, 1536
.pd3_loop:
        mov eax, ebx
        add eax, ecx
        shl eax, 21
        or eax, 0x83
        mov dword [page_table_pd3 + ecx*8], eax
        mov dword [page_table_pd3 + ecx*8 + 4], 0
        inc ecx
        cmp ecx, 512
        jne .pd3_loop

        ret

enable_paging:
        ; debug: before setting CR4
        mov edi, boot_msg_before_cr4
        call print_vga
        mov eax, cr4
        ; enable PAE (bit5) and PGE (bit7) to be more compatible with host expectations
        or eax, (1 << 5) | (1 << 7)
        mov cr4, eax
        mov edi, boot_msg_after_cr4
        call print_vga

        ; debug: before loading CR3
        mov edi, boot_msg_before_cr3
        call print_vga
        mov eax, page_table_l4
        and eax, 0xFFFFF000
        mov cr3, eax
        mov edi, boot_msg_after_cr3
        call print_vga

        ; debug: before setting EFER.LME via MSR
        mov edi, boot_msg_before_efer
        call print_vga
        mov ecx, 0xC0000080
        rdmsr
        or eax, 1 << 8
        wrmsr
        mov edi, boot_msg_after_efer
        call print_vga

        ; debug: before enabling PG in CR0
        mov edi, boot_msg_before_cr0
        call print_vga
        mov eax, cr0
        or eax, 1 << 31
        mov cr0, eax
        mov edi, boot_msg_after_cr0
        call print_vga

        ret

error:
        cmp al, "4"
        je .error4
        cmp al, "3"
        je .error3
        cmp al, "2"
        je .error2
        cmp al, "1"
        je .error1

.error2: ; Error loading kernel: The system does not support x86_64. Wrong CPU.  
        mov edi, error2_msg
        call print_vga
        cli
        hlt
.error3:
        mov edi, error3_msg
        call print_vga
        cli
        hlt
.error4:
        mov edi, error4_msg
        call print_vga
        cli
        hlt
.error1:
        mov edi, error1_msg
        call print_vga
        cli
        hlt

print_vga: ; takes string in edi
        mov esi, 0xb8000
        mov edx, 0
        mov cl, 0x07
.loop:
        mov al, [edi]
        test al, al
        jz .done
        
        mov [esi + edx], al
        mov [esi + edx + 1], cl
        add edx, 2
        inc edi
        jmp .loop
.done:
        ret
section .rodata

error1_msg: db "Error loading kernel: no cpuid support.", 0
error2_msg: db "Error loading kernel: your cpu does not support 64 mode.", 0
error3_msg: db "Error loading kernel: code 3. If you see this, please contact the Axon team.", 0
error4_msg: db "Error loading kernel: code 4. If you see this, please contact the Axon team.", 0
boot_msg_start: db "[BOOT] start\n", 0
boot_msg_before_pt: db "[BOOT] before setup_page_tables\n", 0
boot_msg_after_pt: db "[BOOT] after setup_page_tables\n", 0
boot_msg_before_enable: db "[BOOT] before enable_paging\n", 0
boot_msg_after_enable: db "[BOOT] after enable_paging\n", 0
boot_msg_before_cr4: db "[BOOT] before CR4\n", 0
boot_msg_after_cr4: db "[BOOT] after CR4\n", 0
boot_msg_before_cr3: db "[BOOT] before CR3\n", 0
boot_msg_after_cr3: db "[BOOT] after CR3\n", 0
boot_msg_before_efer: db "[BOOT] before EFER\n", 0
boot_msg_after_efer: db "[BOOT] after EFER\n", 0
boot_msg_before_cr0: db "[BOOT] before CR0\n", 0
boot_msg_after_cr0: db "[BOOT] after CR0\n", 0
; ---------------- GDT ----------------
align 8
tmp_gdt:
        dq 0                                          ; null
        dq 0x00AF9A000000FFFF         ; kernel 64-bit code (DPL0)
        dq 0x00AF92000000FFFF         ; kernel data (DPL0)
tmp_gdt_end:

tmp_gdt_ptr:
        dw tmp_gdt_end - tmp_gdt - 1
        dq tmp_gdt

section .text
bits 64
long_mode_start:
        mov ax, 0x10                 ; kernel data selector in tmp_gdt
        mov ss, ax
        mov ds, ax
        mov es, ax
        mov fs, ax
        mov gs, ax

        ; !!! включаем sse чтобы использовать fpu или sse инструкции для установки gdt
        mov rax, cr0
        and rax, ~(1 << 2)           ; CR0.EM = 0 (enable FPU/SSE instructions)
        or  rax,  (1 << 1)           ; CR0.MP = 1 (monitor coprocessor)
        mov cr0, rax

        mov rax, cr4
        or  rax, (1 << 9)            ; CR4.OSFXSR = 1 (FXSAVE/FXRSTOR + SSE)
        or  rax, (1 << 10)           ; CR4.OSXMMEXCPT = 1 (SSE exceptions)
        mov cr4, rax

	lea rsp, [rel stack_top]
	and rsp, -16
	sub rsp, 8
	
	; --- early VGA trace (64-bit) ---
	; print "LONG MODE" and a second marker so we know how far startup reaches
	lea rdi, [rel longmode_msg]
	call print_vga64
	lea rdi, [rel after_paging_msg]
	call print_vga64
	; -------------------------------
	
	cli
        mov rdi, qword [rel multiboot_magic_saved]
        mov rsi, qword [rel multiboot_info_saved]
        call kernel_main

        cli
.hang:
        hlt
        jmp .hang 

; simple 64-bit VGA print routine and messages
section .rodata
align 8
longmode_msg: db "[LONG MODE]\n", 0
after_paging_msg: db "[LONG_MODE_CONT]\n", 0

section .text
bits 64
print_vga64:
    ; rdi -> RIP-relative pointer to NUL-terminated string
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    mov rsi, 0xb8000
    xor rcx, rcx
loop:
    mov al, byte [rdi + rcx]
    test al, al
    jz done
    mov byte [rsi + rcx*2], al
    mov byte [rsi + rcx*2 + 1], 0x07
    inc rcx
    jmp loop
done:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret