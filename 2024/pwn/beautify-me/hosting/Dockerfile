FROM ubuntu:22.04@sha256:f9d633ff6640178c2d0525017174a688e2c1aef28f0a0130b26bd5554491f0da

RUN apt update && apt install -y socat

RUN mkdir /app
RUN useradd ctf

COPY json /app/json
RUN echo "kalmar{that_was_some_truly_beautiful_json_<3}" > /flag-$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32).txt

USER ctf

EXPOSE 1337

CMD socat tcp-l:1337,reuseaddr,fork exec:/app/json,pty,echo=0,raw,iexten=0
