from ruamel import yaml
from ruamel.yaml import scalarstring
from scapy.all import *
from binascii import hexlify
import ruamel.yaml


# yaml format through the class
# https://yaml.readthedocs.io/en/latest/dumpcls.html
class Packet:
    # tag for remove the '!'
    yaml_tag = u'tag:yaml.org,2002:map'

    # kwargs for various length of properties
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    # data to yaml
    @classmethod
    def to_yaml(cls, representer, node):
        for key, value in list(node.kwargs.items()):
            if value is None:
                node.kwargs.pop(key)
        return representer.represent_mapping(cls.yaml_tag, node.kwargs)

    @classmethod
    def from_yaml(cls, constructor, node):
        data = constructor.construct_mapping(node, deep=True)
        return cls(**data)


# find correct protocol for IEEE 802.3 LLC & SNAP
def findPid(hex_pck):
    if int(hex_pck[40:44], 16) == 0x2000:
        return 'CDP'
    elif int(hex_pck[40:44], 16) == 0x2004:
        return 'DTP'
    elif int(hex_pck[40:44], 16) == 0x010B:
        return 'PVSTP+'
    elif int(hex_pck[40:44], 16) == 0x809B:
        return 'AppleTalk'
    else:
        return 'Unknown protocol'


# find correct protocol IEEE 802.3 LLC
def findSap(hex_pck):
    if int(hex_pck[28:33], 16) == 0x4242:
        return 'STP'
    elif int(hex_pck[28:33], 16) == 0xE0E0:
        return 'IPX'
    elif int(hex_pck[28:33], 16) == 0xF0F0:
        return 'NETBIOS'
    else:
        return 'Unknown protocol'


# transform to hex data of the packet
def printHexData(hex_pck):
    hex_data = ""
    num_pairs = 0
    for i in range(0, len(hex_pck), 2):
        hex_data += hex_pck[i] + hex_pck[i + 1]
        num_pairs += 1
        if num_pairs < 16:
            hex_data += " "
        if num_pairs == 16:
            num_pairs = 0
            hex_data += "\n"

    return hex_data.upper().strip()


# Inter-Switch Link, VLAN protocol
def checkISLHeader(hex_pck):
    # destination address DA
    if int(hex_pck[0:10], 16) == 0x01000C0000 or int(hex_pck[0:10], 16) == 0x03000C0000:
        new_hex_pck = hex_pck[52:]
        return new_hex_pck
    else:
        return hex_pck


# list frames into yaml, main logic
def listOfFrames(file_name):
    file = rdpcap('../vzorky_pcap_na_analyzu/' + file_name)

    pck_list = []
    yaml_format = ruamel.yaml.YAML()

    for frame_num, pck in enumerate(file, start=0):

        # transform code to raw data of wireshark
        # hexlify bytes and convert them to the string
        hex_pck = hexlify(bytes(pck)).decode('utf-8')

        hex_pck = checkISLHeader(hex_pck)

        sap_value = None
        pid_value = None

        if int(hex_pck[24:28], 16) >= 0x5DC:
            define_frame_type = 'Ethernet II'
        else:
            if int(hex_pck[28:32], 16) == 0xFFFF:
                define_frame_type = 'IEEE 802.3 RAW'
            elif int(hex_pck[28:32], 16) == 0xAAAA:
                define_frame_type = 'IEEE 802.3 LLC & SNAP'
                pid_value = findPid(hex_pck)
            else:
                define_frame_type = 'IEEE 802.3 LLC'
                sap_value = findSap(hex_pck)

        # sending data of packet to object
        pck_data = Packet(
            frame_number=frame_num,
            len_frame_pcap=len(pck),
            # +4 because of FCS
            len_frame_medium=max(64, len(pck) + 4),
            frame_type=define_frame_type,
            src_mac=':'.join(hex_pck[:12][i:i + 2] for i in range(0, len(hex_pck[:12]), 2)),
            dst_mac=':'.join(hex_pck[12:24][i:i + 2] for i in range(0, len(hex_pck[12:24]), 2)),
            sap=sap_value,
            pid=pid_value,
            hexa_frame=scalarstring.PreservedScalarString(printHexData(hex_pck))
        )

        yaml_format.register_class(Packet)
        pck_list.append(pck_data)

    # data
    header = {
        "name": "PKS2023/24",
        "pcap_name": file_name,
        "packets": pck_list
    }

    # write to the file all data
    with open('yaml_file.yaml', 'w') as yaml_file:
        yaml_format.indent(offset=2, sequence=4)
        yaml_format.dump(header, yaml_file)

    # replace '|-' to '|'
    with open('yaml_file.yaml', 'r') as f:
        content = f.read()
    content = content.replace("|-\n", "|\n")
    with open('yaml_file.yaml', 'w') as f:
        f.write(content)


if __name__ == '__main__':
    listOfFrames('trace-27.pcap')
