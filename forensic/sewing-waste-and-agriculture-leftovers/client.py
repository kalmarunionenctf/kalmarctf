#!/usr/bin/env python3

import socket
import sys
import random

HOST, PORT = "192.168.1.2", 9999
f = open(sys.argv[1],"r")
data = f.read()
f.close()

# Create a socket (SOCK_STREAM means a TCP socket)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    # Connect to server and send data
    sock.connect((HOST, PORT))
    for c in bytes(data, "utf-8"):
        # Null out a lot of bytes randomly from the flag
        if random.random() > 0.2:
            c = 0
        # Send one byte at a time so the flag parts doesn't appear too much together in a single big packet
        sock.send(bytes([c]))
    sock.send(bytes("\n", "utf-8"))

print("Sent:     {}".format(data))
