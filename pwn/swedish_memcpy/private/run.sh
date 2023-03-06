#!/bin/sh
OUT="$(mktemp /tmp/disk.live.bin.XXXXXXXXXX)"
cp ./disk.live.bin "$OUT"

timeout 5 qemu-system-x86_64 \
    -monitor /dev/null \
    -drive format=raw,file="$OUT" \
    -serial stdio \
    -m 512M \
    -display none \
    -no-reboot

rm "$OUT"
