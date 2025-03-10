#!/bin/sh
rm -f table.txt
docker run --rm -w /app -v ./:/app node:10-alpine node --max-old-space-size=4096 gen_table.js