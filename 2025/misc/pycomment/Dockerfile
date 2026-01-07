FROM python:latest

RUN apt-get update && apt-get -y install socat

RUN useradd -u 1000 -m -s /bin/bash user

COPY flag.txt /
RUN chmod 444 /flag.txt

WORKDIR /home/user

COPY code_to_comment.py .
COPY server.py .

RUN chown -R user:user /home/user
USER user:user


CMD socat -T 240 TCP-L:7531,fork,reuseaddr EXEC:"python3 server.py"

