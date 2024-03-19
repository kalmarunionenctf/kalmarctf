FROM ubuntu:22.04

RUN apt update && apt install -y socat qemu-system

RUN mkdir /app
RUN useradd ctf

COPY run.sh initramfs.cpio.gz bzImage /app

USER ctf
WORKDIR /app

EXPOSE 1337

CMD socat tcp-l:1337,reuseaddr,fork exec:/app/run.sh,pty,echo=0,raw,iexten=0
