FROM python:latest

RUN apt-get update && apt-get -y install socat

RUN pip3 install pycryptodome

WORKDIR /app
COPY chal.py .
COPY flag.txt . 

ENTRYPOINT socat -T 15 TCP-L:2257,fork,reuseaddr EXEC:"python3 chal.py"