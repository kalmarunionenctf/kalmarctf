#!/bin/sh
gcc -no-pie -o exploit exploit.c -masm=intel -O2 -fno-stack-protector -fno-tree-loop-distribute-patterns -mmanual-endbr -fmerge-all-constants -g -nostdlib || exit 1

