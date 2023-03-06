run: bootjs.bin
	qemu-system-x86_64 -hda $< -serial stdio

bootjs.bin: bootjs.asm Makefile
	nasm $< -o $@ -fbin -Ox
	stat $@
	xxd $@
