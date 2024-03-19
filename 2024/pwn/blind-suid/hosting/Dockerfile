FROM ubuntu:22.04 AS ubuntu

RUN apt update && apt install -y strace build-essential python3 nano vim

RUN useradd -M -d /home/user user

COPY flag.txt /root
RUN chmod 400 /root/flag.txt
COPY bash.bashrc /etc/bash.bashrc

FROM ghcr.io/google/nsjail/nsjail:latest

RUN useradd user
RUN useradd fakeroot -u 1337

COPY --from=ubuntu / /srv

RUN ln -s pts/ptmx /srv/dev/ptmx
RUN mkdir /srv/app

RUN chown fakeroot:fakeroot -R /srv

COPY minisudo /srv/app/minisudo
RUN chown fakeroot:fakeroot /srv/app/minisudo && chmod 4711 /srv/app/minisudo

COPY chall.cfg /

EXPOSE 1337
CMD /bin/nsjail --config /chall.cfg
