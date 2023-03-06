FROM sagemath/sagemath:latest

USER root

RUN apt-get -qq update \
    && apt-get -qq install -y --no-install-recommends \
    netcat \
    tmux \
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

RUN chmod -R 750 /ctf && \
  chmod 740 /ctf/flag.txt 

RUN dos2unix /etc/xinetd.d/ctf && dos2unix /ctf/challenge.sage && dos2unix /ctf/start.sh && dos2unix /ctf/flag.txt

ENTRYPOINT []
CMD ["/usr/sbin/xinetd", "-dontfork"]

EXPOSE 9999