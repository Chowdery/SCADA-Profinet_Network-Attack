__author__ = 'Nicholas Rodofile'
import xml.etree.ElementTree as ET
file = 'mitm_dnp3_conf.xml'
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


def read_config_dnp3(host_ip):
    global root
    for node in root.findall('node'):
        name = node.get("name")
        if name == host_ip:
            dnp3_dst = node.find('dnp3_dst').text
            dnp3_src = node.find('dnp3_src').text
            return {"dnp3_dst": dnp3_dst, "dnp3_src": dnp3_src}
    return None


def edit_node_dnp3(host_ip, dnp3_src, dnp3_dst):
    global root
    node = root.Element('node', name=host_ip)
    dnp3 = ET.Element('DNP3')
    dnp3.attrib['dnp3_src'] = dnp3_src
    dnp3.attrib['dnp3_dst'] = dnp3_dst
    node.append(dnp3)
    tree.write(file)



def write_config_dnp3(host, dnp3_src, dnp3_dst):
    pass
    # global root
    # for node in root.findall('node'):
    #     root.remove(node)
    # _node = ET.Element('node', {'name': host})
    # _dnp3_src = ET.SubElement(_node, 'dnp3_src')
    # _dnp3_src.text = dnp3_src
    # _dnp3_dst = ET.SubElement(_node, 'dnp3_dst')
    # _dnp3_dst.text = dnp3_dst
    # root.append(_node)
    # print "Saved Configuration"
    # format_xml(root)
    # tree.write(file)


#src, dst = read_config("192.168.1.1")
#write_config_dnp3('192.168.1.1', "1", "10")
#address = read_config_dnp3("192.168.1.1")
#if address is not None:
#    print address['dnp3_src'], address['dnp3_dst']