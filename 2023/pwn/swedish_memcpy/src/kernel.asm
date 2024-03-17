[bits 64]
kernel_virt_base equ 0xFFFFFFFF80200000
userspace_limit equ 0x2000
org kernel_virt_base
kernel_start:
dq kernel_virt_end - kernel_virt_base - 8
    ; Make address userspace addrspace accessible to userspace
    or byte [0x1000], 4
    or byte [0x2000], 4
    mov rdi, 0x5000
    mov rax, 0x8007
    stosq
    mov rax, 0x9007
    stosq
    mov rcx, 0x200 - 2
    mov rax, 0x0003
.moar:
    stosq
    add rax, 0x1000
    loop .moar
    mov dword [0x3000], 0x5007

    mov rax, cr3
    mov cr3, rax

    ; Zero out userspace memory
    xor rdi, rdi
    mov rcx, 0x2000
    xor al, al
    rep stosb

    lgdt [rel gdtr]
    mov ax, 0x10
    mov ss, ax
    mov ds, ax
    mov fs, ax
    mov es, ax
    mov gs, ax
    push 0x8
    push cs_cont
    retfq

cs_cont:
    lidt [rel idtr]

    mov ax, 0x28
    ltr ax

    ; Let's read some userspace code
read_userspace_code:
    xor rdi, rdi
    mov rcx, 0x1000

read_loop:
    mov dx, 0x3F8 + 5
    in al, dx
    test al, 1
    jz read_loop

    sub dl, 5
    in al, dx

    stosb

    ; mov al, '!'
    ; out dx, al

    loop read_loop

enter_userspace:
    mov ax, 0x20 | 3
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx

    xor rsi, rsi
    xor rdi, rdi
    xor rbp, rbp
    ; rsp gets set in iret

    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    push 0x23     ; ss
    push 0x2000   ; rsp
    push 0x2      ; eflags
    push 0x18 | 3 ; cs
    push 0        ; rip
    iretq

tss_addr equ tss_base - kernel_start + kernel_virt_base

gdt_base:
    dq 0
    dq 0x00A09A0000000000,
    dq 0x0000920000000000,
    dq 0x00A09A0000000000 | (3 << 45),
    dq 0x0000920000000000 | (3 << 45),
    dq (tss_end - tss_base - 1) | ((tss_addr & 0xFFFFFF) << 16) | (9 << 40) | (1 << 47) | (((tss_addr >> 24) & 0xFF) << 56)
    dq (tss_addr >> 32) & 0xFFFFFFFF
gdt_end:

gdtr:
    dw gdt_end - gdt_base - 1
    dq gdt_base

ENOSYS equ -1
EFAULT equ -2

; When `int 0x00` is called from userspace, code execution ends up here.
; Arguments:
;   rax = syscall number to execute
; Returns:
;   rax = ENOSYS if syscall number is too large
syscall_handler:
    cmp rax, (syscall_table_end - syscall_table_base)/8
    jb handle_inrange_syscall
    mov rax, ENOSYS
    iretq
handle_inrange_syscall:
    jmp [syscall_table_base + rax * 8]

syscall_table_base:
    dq exit_handler
    dq write_handler
    dq readchar_handler
    dq get_process_data_handler
syscall_table_end:

; Syscalls

; Shuts down the virtual machine
exit_handler:
    mov al, 0xFE
    out 0x64, al ; QEMU exit

; Prints a string to the screen
; Arguments:
;   rsi = pointer to null terminated string printed on the screen
; Returns:
;   rax = 0 on success,
;   rax = EFAULT on invalid pointer in rsi
write_handler:
    push rdx

    mov rax, EFAULT

    ; Validate source pointer
    cmp rsi, userspace_limit
    ja .end

.write_loop:
    lodsb
    test al, al
    jz .end
    mov dx, 0x3F8
    out dx, al
    out 0x80, al
    jmp .write_loop
.end:
    pop rdx
    xor rax, rax
    iretq

; Reads one character from serial input
; Returns:
;   rcx = 0 if nothing was read
;       rax = serial status byte
;   rcx = 1 if something was read
;       rax = character read
readchar_handler:
    push rdx
    xor rcx, rcx

    mov dx, 0x3F8 + 5
    in al, dx
    test al, 1
    jz .end

    sub dl, 5
    in al, dx
    inc rcx
.end:
    pop rdx
    iretq

; Gets data you're allowed to read from the process data
; That includes and the kernel source.
; Arguments:
;   rdi = destination buffer
;   rcx = number of bytes to read
;   rdx = offset into data buffer to read
; Returns:
;   rax = 0 on success
;   rax = EFAULT if the buffer, offset and size combination isn't valid
get_process_data_handler:
    push rsi

    ; Validate destination + size range
    mov rax, EFAULT
    add rcx, rdi
    jc .end ; Fail on overflow
    cmp rcx, userspace_limit
    ja .end ; Fail if too large
    sub rcx, rdi

    ; Validate offset + size
    add rdx, rcx
    jc .end ; Fail on overflow
    cmp rdx, allowed_data_end - allowed_data_base
    ja .end ; Fail if too large
    sub rdx, rcx

    ; All validated, do the copy
    lea rsi, [allowed_data_base + rdx]
    rep movsb
    xor rax, rax

.end:
    pop rsi
    iretq

; Strings
flag:
    db "flag{goes_here}", 0

; Data userspace can read freely
allowed_data_base:
program_data:
    incbin "procdata.json"
    db 0
kernel_source:
    db 0xA
    incbin "kernel.asm"
allowed_data_end:

syscall_handler_addr equ syscall_handler - kernel_start + kernel_virt_base

; IDT to handle syscalls
align 0x10
idt_base:
    dw syscall_handler_addr & 0xFFFF
    dw 0x08
    db 0x01
    db 0xEE
    dw (syscall_handler_addr >> 16) & 0xFFFF
    dd (syscall_handler_addr >> 32) & 0xFFFFFFFFF
    dd 0
idt_end:

idtr:
    dw idt_end - idt_base
    dq idt_base

; TSS to switch stacks on syscalls, technically not needed if the user doesn't use the red zone
; and since the userspace process is single threaded (no other thread can modify the stack while the)
; kernel is using it. But let's anyways, since it's good practice.
tss_base:
    times 0x24 db 0
    dq interrupt_stack_top
    times 0x66 - 0x2C db 0
tss_end:
    
interrupt_stack_bot:
    times 64 db 0
interrupt_stack_top:

kernel_virt_end:
