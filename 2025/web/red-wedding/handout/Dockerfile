FROM labsai/eddi:latest

# Switch to root user so we can add a getflag SUID binary
USER root 
RUN microdnf install gcc
WORKDIR /
COPY would.c /
COPY flag.txt /

RUN chmod 400 /flag.txt

RUN gcc -o would would.c && \
    chmod 6111 would && \
    rm would.c

# Switch back to the normal user for `labsai/eddi:latest`
USER jboss