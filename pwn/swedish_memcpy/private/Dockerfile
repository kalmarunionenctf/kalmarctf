FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y xinetd qemu-system python3

COPY disk.live.bin /
COPY run.sh /
COPY ynetd /
COPY run.sh /
COPY remote.py /
COPY pow.py /
COPY hashcash.py /

EXPOSE 10001

CMD ./ynetd -p 10001 "/pow.py /usr/bin/timeout 100 /remote.py"
