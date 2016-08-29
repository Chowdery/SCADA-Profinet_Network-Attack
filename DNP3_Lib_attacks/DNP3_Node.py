__author__ = 'Nicholas Rodofile'
from MITM_Lib.Node import *
from DNP3_Lib import *

class DNP3_Node(Node):
    default_DNP3_address = None

    def __init__(self, name="Node", ip_address=Node.default_ip_address, DNP3_address=default_DNP3_address,
                 mac_address=Node.default_ip_mac, sequence=0, acknowledgement=0, DNP3_sequence=0,
                 DNP3_acknowledgement=0, DNP3_app_sequence=0, vendor="", host="", status="down", verbose=1):

        Node.__init__(self, name=name, ip_address=ip_address, mac_address=mac_address, sequence=sequence,
                 acknowledgement=acknowledgement, vendor=vendor, host=host, status=status, verbose=verbose)

        self.DNP3_address = DNP3_address
        self.DNP3_sequence = DNP3_sequence
        self.DNP3_acknowledgement = DNP3_acknowledgement
        self.DNP3_app_sequence = DNP3_app_sequence

    ''' used to initlise N-Map Nodes (nm)'''
    def Node_nm(self, nm, verbose=0):
        #print nm
        if 'ipv4' in nm['addresses']:
            if 'mac' in nm['addresses']:
                mac = nm['addresses']['mac']
                if 'hostname' in nm:
                    hostname_key = 'hostname'
                else:
                    hostname_key = 'hostnames'
                hostname = nm[hostname_key]
                if hostname == '' or hostname is None:
                    hostname = nm['addresses']['ipv4']
                return DNP3_Node(
                    name=hostname,
                    ip_address=nm['addresses']['ipv4'],
                    mac_address=mac,
                    sequence=0,
                    acknowledgement=0,
                    host=nm[hostname_key],
                    verbose=0,
                    DNP3_sequence=0,
                    DNP3_app_sequence=0,
                    DNP3_acknowledgement=0,
                    status=nm['tcp'][20000]['state'],
                )
        return None

    '''Used to initalise from DNP3 packet to connect to slave'''
    def Node_pkt(self, pkt, verbose=0):
        if pkt.haslayer(DNP3):
            return DNP3_Node(
                name="Slave",
                ip_address=pkt[IP].src,
                mac_address=pkt[Ether].src,
                sequence=pkt[TCP].seq,
                acknowledgement=pkt[TCP].ack,
                host="DNP3_Slave",
                verbose=verbose,
                DNP3_sequence=pkt[DNP3].SEQUENCE,
                DNP3_app_sequence= pkt[DNP3ApplicationControl].SEQ,
                DNP3_acknowledgement=0,
                status="Open",
                )
        return None

    def Node_self(self):
        return DNP3_Node(
            name="Self",
            ip_address=pkt[IP].src,
            mac_address=pkt[Ether].src,
            sequence=pkt[TCP].seq,
            acknowledgement=pkt[TCP].ack,
            host="DNP3_Slave",
            verbose=verbose,
            DNP3_sequence=pkt[DNP3].SEQUENCE,
            DNP3_app_sequence= pkt[DNP3ApplicationControl].SEQ,
            DNP3_acknowledgement=0,
            status="Open",
            )


    def show_all(self):
        print "-------------------------------"
        print self.name, "(DNP3)"
        print "-------------------------------"
        print "IP Address\t:", self.ip_address
        print "Mac Address\t:", self.mac_address
        print "DNP3 Address:", self.DNP3_address
        print "Vendor\t\t:", self.vendor
        print "Seq\t\t\t:", self.sequence
        print "Ack\t\t\t:", self.acknowledgement, "\n"

    def init_DNP3_address(self, pkt):
        if pkt.haslayer(DNP3):
            if self.verbose:
                print self.name, "DNP3 Address configured"
            self.DNP3_address = pkt[DNP3].DESTINATION

    def spoof(self, packet, source_node):
        if self.DNP3_address is None:
            self.init_DNP3_address(packet)
        if packet.haslayer(Ether):
            packet[Ether].dst = self.mac_address
            packet[Ether].src = source_node.mac_address
            DNP3_app_type = ''
            if packet.haslayer(TCP):
                self.sequence = packet[TCP].seq
                self.acknowledgement = packet[TCP].ack
                self.window_size = packet[TCP].window
                for opt in packet.getlayer(TCP).options:
                    if "Timestamp" in opt:
                        self.timestamp = opt[1][0]
                        self.timestamp_echo_response = opt[1][1]
                if packet.haslayer(DNP3Transport):
                    self.DNP3_sequence = packet[DNP3Transport].SEQUENCE
                    if packet.haslayer(DNP3ApplicationResponse):
                        self.DNP3_app_sequence = packet[DNP3ApplicationResponse].Application_control.SEQ
                        DNP3_app_type = "Response"
                    elif packet.haslayer(DNP3ApplicationRequest):
                        self.DNP3_app_sequence = packet[DNP3ApplicationRequest].Application_control.SEQ
                        DNP3_app_type = "Request"

            if self.verbose:
                print "Forwarding from", self.name, "(DNP3 "+str(self.DNP3_address)+")"
                if packet.haslayer(DNP3Transport):
                    print "DNP3", DNP3_app_type
                    print "Seq: ", self.DNP3_sequence, "\tApp:", self.DNP3_app_sequence
                    print "timestamp:", self.timestamp
                else:
                    print "TCP"
            self.spoofer.spoof(packet)
        else:
            self.error("No Ethernet Layer! : ", packet.summary())
        return packet


def init_dnp3_nodes(nodes, hosts_found):
    hosts = {}
    node = DNP3_Node()
    for host in hosts_found:
        host_node = node.Node_nm(nodes[host], 1)
        if host_node is not None:
            hosts[host] = host_node
    return hosts