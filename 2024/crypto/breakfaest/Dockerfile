FROM ubuntu:22.04@sha256:f9d633ff6640178c2d0525017174a688e2c1aef28f0a0130b26bd5554491f0da

RUN apt update && apt install -y socat rustc cargo

RUN mkdir /app
RUN useradd ctf

COPY flag /app/flag
COPY breakfaest-chal /app/breakfaest-chal
RUN chmod -R g=+rX,o=+rX /app
RUN cd /app/breakfaest-chal && cargo build --release

USER ctf

EXPOSE 8008

CMD cd /app && socat tcp-l:8008,reuseaddr,fork exec:./breakfaest-chal/target/release/breakfaest,pty,echo=0,iexten=0,rawer
