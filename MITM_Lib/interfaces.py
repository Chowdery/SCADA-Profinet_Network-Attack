import sys
import socket
import fcntl
import struct
import array

def get_mac(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def all_interfaces():
    is_64bits = sys.maxsize > 2**32
    struct_size = 40 if is_64bits else 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8 # initial value
    while True:
        bytes = max_possible * struct_size
        names = array.array('B', '\0' * bytes)
        outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', bytes, names.buffer_info()[0])
        ))[0]
        if outbytes == bytes:
            max_possible *= 2
        else:
            break
    namestr = names.tostring()
    interfaces = [(namestr[i:i+16].split('\0', 1)[0],
             socket.inet_ntoa(namestr[i+20:i+24]))
            for i in range(0, outbytes, struct_size)]

    ifconfigs = {}
    for i in interfaces:
        ifconfigs[i[0]] = {"ipv4": i[1], "mac": get_mac(i[0])}
    return ifconfigs

def display_interfaces():
    interfaces = all_interfaces()
    index = 1
    print "********** Interfaces Available *********"
    for interface, config in interfaces.items():
        print " ", index, " :", interface, "\t", config["ipv4"]
        index += 1
    print "*****************************************"
    return interfaces

def select_interface():
    interfaces = display_interfaces()
    maximum = len(interfaces)
    selected = False
    interface = 0
    while selected is False:
        interface = int(raw_input("Select an interface (1 - " + str(maximum) + ")\n>"))
        if interface > 0 and interface <= maximum:
            selected = True

    return interfaces.keys()[interface-1]
