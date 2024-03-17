getchar equ 0x7C68

[org 0x7ce7]
	pop di
	mov di, .end
	mov cx, 0x4100
	push di
.loop:
	call getchar
	stosb
	cmp al, 0xD
	inc dx
	inc dx
	loop .loop
.end:
