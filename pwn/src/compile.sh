#!/bin/bash
gcc main.c rop_lang.c rop_lang.h -s -z relro -z now -o robber -fstack-protector
