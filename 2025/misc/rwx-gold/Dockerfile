FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y python3 python3-pip gcc
RUN pip3 install flask==3.1.0 --break-system-packages

WORKDIR /
COPY flag.txt /
RUN chmod 400 /flag.txt

COPY would.c /
RUN gcc -o would would.c && \
    chmod 6111 would && \
    rm would.c

WORKDIR /app
COPY app.py .

RUN useradd -m user
USER user

CMD ["python3", "app.py"]
