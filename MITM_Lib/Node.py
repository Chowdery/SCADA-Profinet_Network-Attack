__author__ = 'Nicholas Rodofile'
from scapy.all import *
from netaddr import *


class Node(object):
    default_ip_address = "127.0.0.1"
    default_ip_mac = "FF:FF:FF:FF:FF:FF"

    """ Node class, features of a networked device"""
    def __init__(self, name="Node", ip_address=default_ip_address, mac_address=default_ip_mac, sequence=0,
                 acknowledgement=0, vendor="", host="", status="down", verbose=1):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.sequence = sequence
        self.acknowledgement = acknowledgement
        self.timestamp = 0
        self.timestamp_echo_response = 0
        self.name = name
        self.verbose = verbose
        self.vendor = vendor
        self.window_size = 0
        self.spoofer = None
        if self.mac_address is not self.default_ip_mac:
            try:
                oui = EUI(self.mac_address).oui
                self.vendor = oui.registration().org
            except NotRegisteredError:
                pass
        self.host = host
        self.mac_address = self.mac_address.lower()
        self.status = status

    def Node_nm(self, nm, verbose, port=20000):
        if 'ipv4' in nm['addresses']:
            if 'mac' in nm['addresses']:
                mac = nm['addresses']['mac']
                hostname = nm['hostnames']
                if hostname == '' or hostname is None:
                    hostname = nm['addresses']['ipv4']
                return Node(
                    name=hostname,
                    ip_address=nm['addresses']['ipv4'],
                    mac_address=mac,
                    sequence=0,
                    acknowledgement=0,
                    host=nm['hostnames'],
                    status=nm[u'tcp'][port]['state'],
                    verbose=verbose
                )
        return None


    """ Error Message function"""
    def error(self, msg, summary=""):
        print '\033[91m' + msg + '\033[0m' + summary

    def forward_IP_config(self, packet, source_node):
        if packet.haslayer(IP):
            packet[IP].dst = self.ip_address
            packet[IP].src = source_node.ip_address
        else:
            self.error("No IP Layer! :", packet.summary())
        return packet

    def forward_Ether_config(self, packet, source_node):
        if packet.haslayer(Ether):
            packet[Ether].dst = self.mac_address
            packet[Ether].src = source_node.mac_address
            if self.verbose:
                print "Forwarding to " + self.name + "\n"
        else:
            self.error("No Ethernet Layer! : ", packet.summary())
        return packet

    def forward_Ether(self, packet, source_node):
        if packet.haslayer(Ether):
            packet[Ether].dst = self.mac_address
            packet[Ether].src = source_node.mac_address
            if packet.haslayer(TCP):
                self.sequence = packet[TCP].seq
                self.acknowledgement = packet[TCP].ack
            if self.verbose:
                print "Forwarding to", self.name
                print "Seq: ", self.sequence
                print "Ack:", self.acknowledgement,  "\n"

            sendp(packet, verbose=0)
        else:
            self.error("No Ethernet Layer! : ", packet.summary())
        return packet

    """ Forwarding Configuration:
        Prepare a network packet (scapy.Packet) for forwarding from a defined source node
    """
    def forwarding_config(self, packet, source_node):
        packet = self.forward_Ether_config(packet, source_node)
        packet = self.forward_IP_config(packet, source_node)
        return packet

    def update_node_sequence(self, packet):
        if packet.haslayer(TCP):
            self.sequence = packet[TCP].seq
            self.acknowledgement = packet[TCP].ack

        else:
            self.error("No TCP layer! : ", packet.summary())

    def update_packet_sequence(self, packet):
        if packet.haslayer(TCP):
            packet[TCP].seq = self.sequence
            packet[TCP].ack = self.acknowledgement
        else:
            self.error("No TCP layer! : ", packet.summary())

        return packet

    def show_sequence(self):
        print self.name
        print "Seq\t:", self.sequence
        print "Ack\t:", self.acknowledgement

    def show(self):
        print "-------------------------------"
        print self.name
        print "-------------------------------"
        print "IP Address\t:", self.ip_address
        print "Mac Address\t:", self.mac_address
        print "Seq\t\t\t:", self.sequence
        print "Ack\t\t\t:", self.acknowledgement, "\n"

    def show_all(self):
        print "-------------------------------"
        print self.name
        print "-------------------------------"
        print "IP Address\t:", self.ip_address
        print "Mac Address\t:", self.mac_address
        print "Vendor\t\t:", self.vendor
        print "Seq\t\t\t:", self.sequence
        print "Ack\t\t\t:", self.acknowledgement, "\n"

    def summary(self):
        return self.ip_address + "\t" + self.mac_address + " " + self.vendor + " " + self.status

    def repair_arp(self, connected_node):
        arp = ARP()
        arp.op = 2

        arp.psrc = connected_node.ip_address
        arp.pdst = self.ip_address
        arp.hwdst = self.mac_address
        arp.hwsrc = connected_node.mac_address
        send(arp, verbose=0)
        if self.verbose == 1:
            print self.name, "ARP Repaired"

    def poisoned_arp(self, spoofed_node, attacker):
        arp = ARP()
        arp.op = 2
        arp.psrc = spoofed_node.ip_address
        arp.pdst = self.ip_address
        arp.hwdst = self.mac_address
        arp.hwsrc = attacker.mac_address
        return arp

    def spoof(self, packet, source_node):
        if packet.haslayer(Ether):
            packet[Ether].dst = self.mac_address
            packet[Ether].src = source_node.mac_address
            if packet.haslayer(TCP):
                self.sequence = packet[TCP].seq
                self.acknowledgement = packet[TCP].ack
                ### got timestamp
                for opt in packet.getlayer(TCP).options:
                    if "Timestamp" in opt:
                        self.timestamp = opt[1][0]
                        self.timestamp_echo_response = opt[1][1]
            if self.verbose:
                print "Forwarding from", self.name
                print "Seq: ", self.sequence, "\tAck:", self.acknowledgement
                print "timestamp:", self.timestamp
            self.spoofer.spoof(packet)
        else:
            self.error("No Ethernet Layer! : ", packet.summary())
        return packet


def init_nodes(nodes, hosts_found):
    hosts = {}
    node = Node()
    for host in hosts_found:
        host_node = node.Node_nm(nodes[host], 1)
        if host_node is not None:
            hosts[host] = host_node
    return hosts
