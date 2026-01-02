; Alphix kernel
; 256 ISR stubs for x86_64
; cpu/isr.asm

BITS 64
        DEFAULT REL

%macro PUSH_REGS 0
        push rax
        push rcx
        push rdx
        push rbx
        push rbp
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
%endmacro

%macro POP_REGS 0
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        pop rdx
        pop rcx
        pop rax
%endmacro

extern isr_dispatch

section .text

%define ISR_ATTR 0x8E ; not used here but for documentation

; Список векторов с CPU error-code
%define ERR_VECTORS {8,10,11,12,13,14,17}

%macro ISR_NOERR 1
isr%1:
        PUSH_REGS
        xor rax, rax
        push rax                        ; fake error code
        mov rax, %1
        push rax                        ; interrupt number
        mov rdi, rsp                ; rdi -> cpu_registers_t
        call isr_dispatch
        add rsp, 16                 ; pop vector + error code
        POP_REGS
        iretq
%endmacro

%macro ISR_ERR 1
isr%1:
        ; For exceptions with CPU-pushed error code (e.g., #PF):
        ; entry stack layout: [error_code][RIP][CS][RFLAGS][RSP][SS]
        ; Our cpu_registers_t expects:
        ;   interrupt_number, error_code, r15..rax, RIP, CS, RFLAGS, RSP, SS
        ;
        ; To avoid shifting the layout by keeping TWO error codes on stack,
        ; we remove the CPU error code first and re-push it in the expected place.
        mov rax, [rsp]                  ; save CPU error code
        add rsp, 8                      ; drop original error code (iretq frame now starts with RIP)
        PUSH_REGS
        push rax                        ; error_code
        mov rax, %1
        push rax                        ; interrupt_number
        mov rdi, rsp                    ; rdi -> cpu_registers_t
        call isr_dispatch
        add rsp, 16                     ; pop interrupt_number + error_code
        POP_REGS
        iretq
%endmacro

; Генерация 256 ISR
section .text
%assign i 0
%rep 256
        %if (i == 8) || (i == 10) || (i == 11) || (i == 12) || (i == 13) || (i == 14) || (i == 17)
                ISR_ERR i
        %else
                ISR_NOERR i
        %endif
%assign i i+1
%endrep

section .rodata
global isr_stub_table
isr_stub_table:
%assign i 0
%rep 256
        dq isr%+i
%assign i i+1
%endrep 