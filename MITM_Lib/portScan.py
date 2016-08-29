#!/bin/python 

import commands
import nmap
import re
from Node import *


def getLocalhostIP(interface):
    if interface is not None:
        interface_ip = commands.getoutput("ip address show dev " + interface).split()
        interface_ip = interface_ip[interface_ip.index('inet') + 1].split('/')[0]
        return interface_ip
    else:
        print "ERROR interface is None"
        quit()


def getNetworkInfo(ip_address=None, ports="80", verbose=1):
    if ip_address is not None:
        address = re.findall(r"[\d']+", ip_address)
        address[3] = '0-255'
        ip_range = '.'.join(map(str,address))
        if verbose:
            print "Searching Range [",ip_range,"] at port/s", ports, '...\n'
        nm = nmap.PortScanner()
        nm.scan(ip_range, ports, "")
        return nm
    else:
        print "ERROR No IP Address"
        quit()


def scan_interface(interface='eth0', verbose=1):
    ip_address = getLocalhostIP(interface)
    if verbose:
        print "Your Address is [", ip_address ,"]..."
    nm = getNetworkInfo(ip_address, '20000', verbose)

    host_info = []
    hosts = nm.all_hosts()

    for host in hosts:
        host_info.append(nm[host]['addresses'])

    if verbose:
        index = 1
        print "********** Addresses Available *********"
        for host in host_info:
            if 'ipv4' in host:
                if 'mac' in host:
                    print " ", index ," :", host['ipv4'], host['mac']
                else:
                    print " ", index ," :", host['ipv4'], '\033[91m' + "* NO MAC AVAILABLE *" + '\033[0m'
                index += 1
        print "****************************************"
    return host_info


def get_all_network_nodes(interface="eth0", ip_address=None, port='80'):
    if ip_address is None:
        ip_address = getLocalhostIP(interface)
    nm = getNetworkInfo(ip_address, port)
    #hosts = nm.all_hosts()
    #for host in hosts:
    #    print nm[host]
    return nm




