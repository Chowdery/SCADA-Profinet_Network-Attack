iptables --flush
iptables -A OUTPUT -p TCP --tcp-flags RST RST --destination-port 502 -j DROP
iptables -A OUTPUT -p TCP --tcp-flags RST RST --destination-port 20000 -j DROP
iptables -A OUTPUT -p TCP --tcp-flags RST RST --destination-port 80 -j DROP
iptables -A OUTPUT -p TCP --tcp-flags RST RST --destination-port 1024 -j DROP
iptables -A OUTPUT -p icmp --icmp-type 3/3 -j DROP
iptables --list