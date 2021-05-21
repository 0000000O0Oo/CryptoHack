#!/usr/bin/python3

import telnetlib
import json

host = "socket.cryptohack.org"
port = 11112

connection = telnetlib.Telnet(host, port)

def recvData():
    return connection.read_until(b"\n")

parameter = {
        "buy" : "flag"
        }

print(recvData())
print(recvData())
print(recvData())
print(recvData())

parameter2Json = json.dumps(parameter)

connection.write(parameter2Json.encode())
#print(recvData().decode())
print(json.loads(recvData().decode()))
