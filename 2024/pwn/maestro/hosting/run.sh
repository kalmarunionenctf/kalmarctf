#!/bin/bash

echo "Please provide a URL to download exploit:"
read -r URL

TEMPFILE=$(mktemp)

if [[ $URL =~ ^https?:// ]]; then
    curl -k -s -o "$TEMPFILE" --max-filesize 10M -A 'KalmarCTF' -- "$URL"
fi

exec timeout --foreground 300 qemu-system-i386 \
    -m 128M \
    -cdrom kernel.live.iso \
    -boot order=d \
    -no-reboot \
    -nographic \
    -monitor none \
    -drive file="$TEMPFILE",format=raw

