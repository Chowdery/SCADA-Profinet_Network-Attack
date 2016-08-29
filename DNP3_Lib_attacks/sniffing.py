import threading
from scapy.all import *
import datetime
import os
import signal
import subprocess

class DatasetSniffer(threading.Thread):
    def __init__(self, iface, local_dir='.', filename=str(datetime.datetime.now()), stop_filter=None, name=None):
        threading.Thread.__init__(self)
        self.iface = iface
        self.filename = filename
        self.local_dir = local_dir
        self.stop_filter = stop_filter
        self.writer = PcapWriter(local_dir+"/"+filename+".pcap", append=True, sync=True)
        if name is not None:
            self.name = name


    def run(self):
        sniff_interface(self.writer.write, self.iface, self.stop_filter)


def sniff_interface(write, iface, stop_filter):
    sniff(store=0, prn=write, iface=iface, stop_filter=stop_filter)


class DatasetManager(object):
    def __init__(self, directory, interfaces, name):
        self.directory = directory
        self.interfaces = interfaces
        self.sniffers = {}
        self.stop_sniffing = False
        self.name = name

    def init_sniffers(self):
        for iface in self.interfaces:
            #self.sniffers.append(DatasetSniffer(self.interfaces[iface], self.directory, iface, self.stop_filter, iface))
            cmd = "tcpdump -ni " + self.interfaces[iface] + " -s 65535 -w " + self.directory + '/' + iface + ".pcap"
            self.sniffers[iface] = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
    def stop_filter(self, p):
        if self.stop_sniffing:
            return True
        else:
            return False

    def start(self):
        self.init_sniffers()

        # for sniffer in self.sniffers:
        #     sniffer.start()

    def stop(self):
        self.stop_sniffing = True
        for sniffer in self.sniffers:
            os.killpg(os.getpgid(self.sniffers[sniffer].pid), signal.SIGTERM)

if __name__ == "__main__":
    local = "dataset/"
    directory = local + str(datetime.datetime.now().strftime("%Y%m%d%H%M%S"))
    os.makedirs(directory)
    #DatasetSnifferExit = False
    # Create new threads
    interfaces = {
        'attacker': "eth0",
        'master': "eth1",
        'slave': "eth2"
    }
    manager = DatasetManager(directory, interfaces, "test")
    manager.start()
    time.sleep(30)
    manager.stop()