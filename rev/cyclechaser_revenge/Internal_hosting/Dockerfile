FROM ubuntu

USER root

RUN apt-get -qq update \
    && apt-get -qq install -y --no-install-recommends \
    netcat \
    tmux \
    gcc \
    libc6-dev \
    vim \
    xinetd \
    python3 \
    python3-pip \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /ctf
WORKDIR /ctf

RUN echo "Connection blocked" > /etc/banner_fail
COPY ctf.xinetd /etc/xinetd.d/ctf
COPY ./src /ctf/

RUN chmod -R 750 /ctf 

RUN dos2unix /etc/xinetd.d/ctf && dos2unix /ctf/chal.c && dos2unix /ctf/start.sh && dos2unix /ctf/flag.txt

RUN gcc -Wall -Werror -D REVENGE chal.c -o cyclechaserrevenge

CMD ["/usr/sbin/xinetd", "-dontfork"]

EXPOSE 9999