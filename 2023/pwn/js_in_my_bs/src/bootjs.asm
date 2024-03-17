stack equ 0xFFF0

[bits 16]
org 0x7C00
_start:
    mov sp, stack
    mov cx, 1

; Parses and executes a line
eval_statement:
    call newline
    mov al, '>'
    call putch
    mov al, ' '
    call putch
    call read_var ; read and get a variable
    push si ; Variable ptr
    call read_key
    push ax ; Operator
    call eval_expr
    ; Expr in bx
    pop ax ; Operator
    pop si ; variable ptr

    cmp al, '('
    je .fcall
    cmp al, '='
    jne eval_statement

.assignment:
    mov [si], bx
    jmp eval_statement
.fcall:
    call [si] ; This better be calling log_func ;)
    jmp eval_statement

; Read a value
; If a number 0-9 is entered, that value is returned, otherwise
; the variable with the name of the key hit is returned
; ----- IN -----
; Nothing
; ----- OUT -----
; Value in ax
; ----- CLOBBER -----
; clobbers of read_key and get_var
; -----
read_value:
    call read_key
    cmp al, '9'
    jg .value_is_var
.value_is_int:
    sub al, '0'
    xor ah, ah
    ret
.value_is_var:
    call get_var
    mov ax, [si]
    ret

; Read and evaluate an expression
eval_expr:
    ; lhs
    call read_value
    push ax

    ; Infix operator
    call read_key

    cmp al, '+'
    je .addition

    cmp al, '-'
    je .subtraction

    ; Single value, no operator
    pop bx
    ret

.addition:
    call eval_expr
    pop ax
    add bx, ax
    ret

.subtraction:
    call eval_expr
    push bx
    pop ax
    pop bx
    sub bx, ax
    ret

; Get a key, char in al
read_key:
    mov dx, 0x3F8 + 5
    in al, dx
    test al, 1
    jz read_key
    sub dl, 5
    in al, dx
    out dx, al
    cmp al, ' '
    je read_key
    ret

; Print a carriage return and newline
; Clobbers dx and al
newline:
    mov al, 0xA ; Newline
    jmp putch

; Log a value in hex
; ----- IN -----
; Value: bx
; ----- CLOBBER -----
; al, dx
log_func:
    call newline
    mov al, bh
    shr al, 4
    call log_nibble
    mov al, bh
    and al, 0xF
    call log_nibble
    mov al, bl
    shr al, 4
    call log_nibble
    mov al, bl
    and al, 0xF
; Log a nibble in al
log_nibble:
    xor ah, ah
    mov si, ax
    add si, hex
    lodsb
; Log a character in al
putch:
    mov dx, 0x3F8
    out dx, al
    ret

hex:
    db "0123456789ABCDEF"

; Get or read variable ptr
; If variable isn't found, adds it with undefined value
; ----- IN -----
; Get: Variable name in al
; Read: Nothing
; ----- OUT -----
; Variable pointer in si
; ----- CLOBBER -----
; Clobbers dl
; -----
read_var:
    call read_key ; Get variable name
get_var:
    mov dl, al
    mov si, vartab
    push cx
.search_loop:
    lodsb
    cmp al, dl ; Compare variable name
    je .restore_cx_ret
    lodsw ; Discard variable value
    loop .search_loop
.insert:
    mov [si], dl
    lodsb
    pop cx
    inc cx
    jmp .ret
.restore_cx_ret:
    pop cx
.ret:
    ret

vartab:
    db 'l'
    dw log_func

times 510-($-$$) db 0x41
dw 0xaa55
db "kalmar{this_would_be_a_nice_addon_to_all_efi_shells_right?}"
