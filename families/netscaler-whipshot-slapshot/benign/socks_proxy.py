#!/usr/bin/env python
import socket, select
def relay(a,b):
    while True:
        r,_,_=select.select([a,b],[],[])
        if a in r: b.sendall(a.recv(4096))
        if b in r: a.sendall(b.recv(4096))
srv=socket.socket(); srv.bind(("0.0.0.0",1080)); srv.listen(50)
