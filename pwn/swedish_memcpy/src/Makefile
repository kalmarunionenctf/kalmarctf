all: disk.live.bin disk.redacted.bin

clean:
	rm -f kernel.redacted.asm kernel.live.asm disk.redacted.bin disk.live.bin

%.bin: %.asm
	nasm $< -o $@
	truncate -s %512 $@

kernel.redacted.asm: kernel.asm Makefile
	sed 's#flag{goes_here}#kalmar{fakeflagfakeflagfakeflagfakeflagfakeflagfakefl}#' $< > $@

kernel.live.asm: kernel.asm Makefile
	sed 's#flag{goes_here}#kalmar{th15_1s_7h3_m0st_us3fu1_x86_featur3_y3s_1_know}#' $< > $@

disk.%: bootelf kernel.%
	cat $^ > $@

