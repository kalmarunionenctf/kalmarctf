#!/bin/bash

docker build -o maestro-build -t maestro -f Dockerfile.build . || exit 1

if [ ! -d ./initramfs ]; then
    tar -xf initramfs.tar.xz
fi

# Build init
gcc -no-pie -o ./initramfs/sbin/init init.c -masm=intel -O2 -fno-stack-protector -fno-tree-loop-distribute-patterns -mmanual-endbr -fmerge-all-constants -s -nostdlib || exit 1

cp ./maestro-build/maestro ./iso/boot/maestro
cp ./maestro-build/libserial.so ./initramfs/lib/modules/maestro-0.1.0/default/libserial.so

pushd initramfs
find . -print0 | cpio --null -ov --format=bin --owner=+0.+0 > ../iso/boot/initramfs.cpio
popd

grub-mkrescue -o kernel.iso --fonts= iso/

