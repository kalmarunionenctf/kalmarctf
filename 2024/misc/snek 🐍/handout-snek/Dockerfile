FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt update && apt install --no-install-recommends -y \
  iproute2 \
  socat \
  netcat-openbsd \
  sudo \
  build-essential \
  && rm -rf /var/lib/apt/lists/*

COPY flag /flag
RUN chown root:root /flag && chmod 400 /flag

COPY readflag.c /readflag.c
RUN gcc -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 /readflag.c -o /readflag \
  && chown root:root /readflag && chmod 4755 /readflag

COPY ./game.sh /game.sh
RUN chmod +x /game.sh
RUN useradd --shell /bin/false ctf

# TODO: I ran these commands to make IPv6 work:
#ip add add local 2a01:4f8:1c1c:d3ed::1/64 dev lo
#ip route add local 2a01:4f8:1c1c:d3ed::1/64 dev eth0
#sysctl -w net.ipv6.ip_nonlocal_bind=1
# But IPv6 is not really a part of the challenge, so you can just remove "-6" to make it work locally
#CMD ["socat", "-6", "TCP-LISTEN:1336,fork", "SYSTEM:'echo \"game spawned at http://$SOCAT_SOCKADDR:1337\" ; sudo -u ctf /game.sh'"]
CMD ["socat", "TCP-LISTEN:1336,fork", "SYSTEM:'echo \"game spawned at http://$SOCAT_SOCKADDR:1337\" ; sudo -Eu ctf /game.sh'"]
