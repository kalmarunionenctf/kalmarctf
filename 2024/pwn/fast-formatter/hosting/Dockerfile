FROM python:3.10-slim@sha256:4bd9a0e5da619b155a214342bb4fdc774a947fec9061016a123fa4073431c9cb

RUN apt update && apt install -y socat

RUN mkdir /app
RUN useradd ctf

COPY chall.py sandbox.py fastformat.cpython-310-x86_64-linux-gnu.so /app
RUN echo "kalmar{Escaping_Python_jails_with_PWN!!}" > /flag-$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32).txt

USER ctf

EXPOSE 1337

CMD socat tcp-l:1337,reuseaddr,fork exec:/app/chall.py,pty,echo=0,raw,iexten=0
