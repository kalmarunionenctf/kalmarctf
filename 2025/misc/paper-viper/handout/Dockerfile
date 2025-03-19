FROM python:latest

RUN apt-get update && apt-get -y install socat
RUN pip3 install asteval==1.0.6 numpy

WORKDIR /
COPY getflag.c /
COPY flag.txt /

RUN chmod 400 /flag.txt

RUN gcc -o getflag getflag.c && \
    chmod 6111 getflag && \
    rm getflag.c

WORKDIR /app
COPY chal.py .

RUN useradd user
USER user

CMD socat -T 120 TCP-L:6843,fork,reuseaddr EXEC:"python3 /app/chal.py",stderr
