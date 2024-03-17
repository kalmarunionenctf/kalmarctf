putchar equ 0x7CAF

[org 0x7ce7 + 0x12]
	mov ax, 0x0201
	mov cx, 0x0002
	mov dx, 0x80
	mov bx, 0x7E00
	int 0x13
	push bx
	pop si
.puts_loop:
	lodsb
	cmp al, 0
.hang:
	je .hang
	call putchar
	jmp .puts_loop
