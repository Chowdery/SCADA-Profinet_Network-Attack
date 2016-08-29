#!/usr/bin/bash

iptables -A INPUT -i eth1 -j DROP
iptables -A INPUT -i eth2 -j DROP


