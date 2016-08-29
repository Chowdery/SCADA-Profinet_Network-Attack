__author__ = 'Nicholas Rodofile'
from portScan import *

import xml.etree.ElementTree as ET
file = 'mitm_conf.xml'
tree = ET.parse(file)
root = tree.getroot()

from xml.dom import minidom

def format_xml(elem):
    """Return a pretty-printed XML string for the Element.
        http://pymotw.com/2/xml/etree/ElementTree/create.html
    """
    rough_string = ET.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="\t")


def read_config(port=20000):
    nodes = {}
    for node in root.findall('node'):
        name = node.get("name")
        nodes[name] = {'addresses': {}}
        nodes[name]['addresses']['ipv4'] = node.find('ip_address').text
        nodes[name]['addresses']['mac'] = node.find('mac_address').text
        nodes[name]['hostnames'] = node.find('hostnames').text
        nodes[name]["tcp"] = {port: {}}
        if node.find('state') is not None:
            nodes[name]['tcp'][port]['state'] = node.find('state').text
    return nodes

def write_config(nodes):
    for node in root.findall('node'):
        name = node.get("name")
        ip = nodes[name]['ipv4']
        mac = nodes[name]['mac']
        node.find('ip_address').text = ip
        node.find('mac_address').text = mac
    tree.write(file)


def write_nm_config(nm):
    for node in root.findall('node'):
        root.remove(node)

    hosts_found = nm.all_hosts()
    for host in hosts_found:
        if 'mac' in nm[host]['addresses']:
            _node = ET.Element('node', {'name': host})
            _ip_address = ET.SubElement(_node, 'ip_address')
            _ip_address.text = nm[host]['addresses']['ipv4']
            _mac_address = ET.SubElement(_node, 'mac_address')
            _mac_address.text = nm[host]['addresses']['mac']
            _hostname = ET.SubElement(_node, 'hostnames')
            _hostname.text = nm[host]['hostnames']
            _state = ET.SubElement(_node, 'state')
            _state.text = nm[host]['tcp'][20000]['state']
            root.append(_node)
    print "Configuration File has updated"
    format_xml(root)
    tree.write(file)




def get_hosts(interface="eth0", port="80"):
    use_conf = None
    nodes_selected = None
    node_keys = None
    option_use_conf = False
    while not option_use_conf:
        use_conf = str(raw_input("Use Nodes From Configuration (y or n) ?\n > "))
        if use_conf == 'y' or use_conf == 'n':
            if use_conf == 'y':
                nodes_selected = read_config()
                node_keys = nodes_selected.keys()
            else:
                nodes_selected = get_all_network_nodes(port=port, interface=interface)
                node_keys = nodes_selected.all_hosts()
            option_use_conf = True
        if use_conf == 'q':
            quit()

    return use_conf, nodes_selected, node_keys, option_use_conf


def display_config_hosts(nodes):
    keys = sorted(nodes.keys())
    index = 0
    for node in keys:
        print index, " > ", nodes[node].summary()
        index += 1
    options = len(keys)
    return options-1, keys


def select_gateway(options, nodes, keys):
    selected_gateway = False
    gateway = None
    while not selected_gateway:
        gateway_option = str(raw_input("Select A Gateway (0 to " + str(options) + ")\n> "))
        if gateway_option.isdigit():
            gw = int(gateway_option)
            if -1 < gw < options+1: # To include last option
                selected_gateway = True
                gateway = nodes[keys[gw]]
                gateway.show_all()
        if gateway_option == 'q':
            quit()
    return gateway


def select_victim(options, nodes, keys):
    selected_victim = False
    victim = None
    while not selected_victim:
        victim_option = str(raw_input("Select A Victim (0 to " + str(options) + ")\n> "))
        if victim_option.isdigit():
            v = int(victim_option)
            if -1 < v < options+1: # To include last option
                selected_victim = True
                victim = nodes[keys[v]]
                victim.show_all()
        if victim_option == 'q':
            quit()
    return victim


def save_nodes_to_config(nodes_selected):
    option_saved_nodes = False
    while not option_saved_nodes:
        save_nodes = str(raw_input("Save all Nodes to Configuration (y or n) ?\n > "))
        if save_nodes == 'y' or save_nodes == 'n':
            if save_nodes == 'y':
                write_nm_config(nodes_selected)
            option_saved_nodes = True
        if save_nodes == 'q':
                quit()


def config_nodes(interface="eth0", port="80", init_nodes_func=init_nodes):
    use_conf, nodes_selected, node_keys, option_use_conf = get_hosts(interface=interface, port=port)
    nodes = init_nodes_func(nodes_selected, node_keys)
    options, keys = display_config_hosts(nodes)
    gateway = select_gateway(options, nodes, keys)
    victim = select_victim(options, nodes, keys)
    if use_conf == 'n':
        save_nodes_to_config(nodes_selected)
    return gateway, victim


def config_nodes_all(interface="eth0", port="80", init_nodes_func=init_nodes):
    use_conf, nodes_selected, node_keys, option_use_conf = get_hosts(interface=interface, port=port)
    nodes = init_nodes_func(nodes_selected, node_keys)
    options, keys = display_config_hosts(nodes)
    gateway = select_gateway(options, nodes, keys)
    victim = select_victim(options, nodes, keys)
    if use_conf == 'n':
        save_nodes_to_config(nodes_selected)
    return gateway, victim, nodes


def scan_for_all_hosts(interface="eth0", port="80", init_nodes_func=init_nodes):
    nodes_selected = get_all_network_nodes(port=port, interface=interface)
    node_keys = nodes_selected.all_hosts()
    nodes = init_nodes_func(nodes_selected, node_keys)
    keys = sorted(nodes.keys())
    print "------------------ Nodes Found ------------------"
    print "#################################################"
    for node in keys:
        print " > ", nodes[node].summary()
    print "#################################################"
    return nodes


#nodes = read_config()
#print nodes
#print nodes['attacker']['mac']
#nodes['master']['mac'] = "10"
#write_config(nodes)