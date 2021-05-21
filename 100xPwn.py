#!/usr/bin/python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
import socket, optparse, json, codecs, base64

def GetArgs():
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", dest="host", help="Host to connect and pwn.")
    parser.add_option("-p", "--port", dest="port", help="Port to connect and pwn.")
    (option, arguments) = parser.parse_args()
    if not option.host:
        parser.error("[-] I need a host to connect and pwn.")
    elif not option.port:
        parser.error("[-] I need a port to connect and pwn.")
    else:
        return option

class Solve:
    #Solve Variables
    #conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    encodingTypes = []
    host = ""
    port = 1234
    value = ""
    encoding = ""
    sendingVal = {"decoded": ""}
    ##GET ENCODING TYPES (I COULD HAVE HARD WRITTEN THEM BUT I DECIDED NOT TO !) 
    #Function Used by GetEncodingTypes

    def ConnectAndParseEncodingTypes(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((self.host, int(self.port)))
        CurrentEncodingName = json.loads(conn.recvfrom(1024)[0].decode())['type']
        if CurrentEncodingName not in self.encodingTypes:
            print(f"[+] Adding {CurrentEncodingName} in encoding list...")
            self.encodingTypes.append(CurrentEncodingName)

    #GetEncodingTypes, calls ConnectAndParse... to get all available types
    def GetEncodingTypes(self):
        print("[+] Getting encoding type...")
        for i in range(0,50):
            self.ConnectAndParseEncodingTypes()
    

    def ConnectAndSolve(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((self.host, int(self.port)))
        for i in range(0,500):
            recvd = conn.recvfrom(1024)[0].decode()
            print(f"rcvd: {recvd}")
            self.value = json.loads(recvd)['encoded']
            self.encoding = json.loads(recvd)['type']
            print(f"[+] Decoding value : {self.value}")
            print("[+] Encoding type : " + self.encoding)
            if self.encoding == "rot13":
                self.sendingVal = {"decoded": codecs.decode(self.value, 'rot_13')}
                conn.send(json.dumps(self.sendingVal).encode())
            elif self.encoding == "hex":
                self.sendingVal = {"decoded": bytes.fromhex(self.value).decode("utf-8")}
                conn.send(json.dumps(self.sendingVal).encode())
            elif self.encoding == "bigint":
                self.sendingVal = {"decoded": bytes.fromhex(self.value[2:]).decode('utf-8')}
                conn.send(json.dumps(self.sendingVal).encode())
                #self.sendingVal['decoded'] = long_to_bytes(self.value).decode()
            elif self.encoding == "utf-8":
                temp = ""
                for b in self.value:
                    temp += chr(b)
                    self.sendingVal = {"decoded": temp}
                conn.send(json.dumps(self.sendingVal).encode())
            elif self.encoding == "base64":
                temp = base64.b64decode(self.value).decode()
                self.sendingVal = {"decoded": temp}
                conn.send(json.dumps(self.sendingVal).encode())
            print(self.sendingVal)
            #conn.send(json.dumps(self.sendingVal).encode())
            self.value = ""
            self.sendingVal = ""
            self.encoding = ""
    #CONSTRUCTOR WILL BE USED TO SOLVE THE CHALLENGE
    def __init__(self):
        args = GetArgs()
        self.host = args.host
        self.port = args.port 
        print("[+] Pwning Challenge...")
        print(f"[+] Host : {self.host}:{self.port}")
        self.GetEncodingTypes()
        print("[+] Done retrieving encoding types...")
        print("[+] Starting 100x Decryption challenge...")
        self.ConnectAndSolve()

def main():
    Challenge = Solve()

main()
