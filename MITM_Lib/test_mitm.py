__author__ = 'Nicholas Rodofile'
from Replay import *

interface = "eth0"

#mitm = MITM_conf()
#pcap_filename = mitm.start()

injection = Injection_conf(pkt_count="100")
injection.start()

#replay = Replay_conf(pkt_count="100")
#replay.process_replayable("mitm/mitm20141125_141643.pcap")
#replay = Replay(interface_selected=interface, gateway=mitm.gateway, victim=mitm.victim,
#                verbose=mitm.verbose, pkt_count=mitm.pkt_count, replayable_pcap=pcap_filename)
#replay.start()





