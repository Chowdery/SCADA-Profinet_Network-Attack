#!/bin/bash
ifconfig eth0 hw ether 00:18:64:02:30:FC
ifconfig eth0 192.168.10.222/24
service networking restart


