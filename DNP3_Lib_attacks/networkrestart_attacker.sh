#!/bin/bash
ifconfig eth0 hw ether 00:10:18:CB:8C:13
ifconfig eth0 192.168.10.66/24
service networking restart


