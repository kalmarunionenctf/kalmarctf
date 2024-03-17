# deployment

FROM ubuntu


RUN mkdir /ctf
WORKDIR /ctf

RUN apt-get -qq update \
    && apt-get -qq install -y --no-install-recommends \
    netcat \
    tmux \
    vim \
    xinetd \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*


RUN echo "Connection blocked" > /etc/banner_fail
COPY ctf.xinetd /etc/xinetd.d/ctf
COPY ./src /ctf/

RUN chmod -R 750 /ctf 

RUN dos2unix /etc/xinetd.d/ctf && dos2unix /ctf/start.sh && dos2unix /ctf/flag.txt


CMD ["/usr/sbin/xinetd", "-dontfork"]

EXPOSE 9999