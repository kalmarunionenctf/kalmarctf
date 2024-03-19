#!/bin/sh

exec timeout --foreground 300 qemu-system-x86_64 \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -append "console=ttyS0 loglevel=0 oops=panic pti=on" \
    -cpu qemu64,+smep,+smap \
    -no-reboot -nographic -monitor none

