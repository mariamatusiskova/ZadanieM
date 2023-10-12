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


def findPort(hex_pck, address_type, dictl):
    IP_length_header = (int(hex_pck[29], 16) * 4 * 2) - (20 * 2)
    if address_type == "src":
        return int(hex_pck[(68 + IP_length_header):(72 + IP_length_header)], 16), findProtocolPort(hex_pck, dictl, (68 + IP_length_header), (72 + IP_length_header))
    elif address_type == "dst":
        return int(hex_pck[(72 + IP_length_header):(76 + IP_length_header)], 16), findProtocolPort(hex_pck, dictl, (72 + IP_length_header), (76 + IP_length_header))


def convertToIP(IP_address):
    address = ""
    len_IP = 0
    for i in range(0, len(IP_address), 2):
        address += str(int(IP_address[i:i+2], 16))
        len_IP += 2
        if len_IP < (len(IP_address) - 1):
            address += "."

    return address


def findIPAddresses(hex_pck, address_type, protocol):
    if protocol == "ARP":
        if address_type == "src":
            return convertToIP(hex_pck[56:64])
        elif address_type == "dst":
            return convertToIP(hex_pck[76:84])
    elif protocol == "IPv4":
        if address_type == "src":
            return convertToIP(hex_pck[52:60])
        elif address_type == "dst":
            return convertToIP(hex_pck[60:68])


# https://www.tutorialspoint.com/How-to-create-a-Python-dictionary-from-text-file
def getDictl(file_path):
    dict_value = {}
    with open(file_path) as file:
        for line in file:
            (hexa, value) = line.split("=")
            dict_value[hexa] = value.strip()
    return dict_value


def findProtocolPort(hex_pck, dict_protocol, position_from, position_to):
    if (hex_pck[position_from:position_to]).upper() in dict_protocol:
        return dict_protocol[(hex_pck[position_from:position_to]).upper()]
    else:
        return


def findProtocol(hex_pck, dict_protocol, position_from, position_to):
    if (hex_pck[position_from:position_to]).upper() in dict_protocol:
        return dict_protocol[(hex_pck[position_from:position_to]).upper()]
    else:
        return 'Unknown protocol'


# # find correct protocol for IEEE 802.3 LLC & SNAP
# def findPid(hex_pck):
#     # https://www.tutorialspoint.com/How-to-create-a-Python-dictionary-from-text-file
#     pid_dict = {}
#     with open("Protocols/l3.txt") as file:
#         for line in file:
#             (hexa, value) = line.split("=")
#             pid_dict[hexa] = value.strip()
#
#         if hex_pck[40:44] in pid_dict:
#             return pid_dict[hex_pck[40:44]]
#         else:
#             return 'Unknown protocol'


# find correct protocol IEEE 802.3 LLC
def findSap(hex_pck, dict_protocol):
    # https://www.tutorialspoint.com/How-to-create-a-Python-dictionary-from-text-file
    if int(hex_pck[28:30], 16) == int(hex_pck[30:32], 16):
        if (hex_pck[28:30]).upper() in dict_protocol:
            return dict_protocol[(hex_pck[28:30]).upper()]
        else:
            return 'Unknown protocol'
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

    dict_l2 = getDictl("Protocols/l2.txt")
    dict_l3 = getDictl("Protocols/l3.txt")
    dict_l4 = getDictl("Protocols/l4.txt")
    dict_l5 = getDictl("Protocols/l5.txt")

    for frame_num, pck in enumerate(file, start=0):

        # transform code to raw data of wireshark
        # hexlify bytes and convert them to the string
        hex_pck = hexlify(bytes(pck)).decode('utf-8')

        hex_pck = checkISLHeader(hex_pck)

        sap_value = None
        pid_value = None
        ether_type = None
        src_ip = None
        dst_ip = None
        protocol = None
        src_port = None
        dst_port = None
        app_protocol = None

        if int(hex_pck[24:28], 16) >= 0x5DC:
            define_frame_type = 'Ethernet II'
            ether_type = findProtocol(hex_pck, dict_l3, 24, 28)
            src_ip = findIPAddresses(hex_pck, "src", ether_type)
            dst_ip = findIPAddresses(hex_pck, "dst", ether_type)
            if ether_type == "IPv4":
                protocol = findProtocol(hex_pck, dict_l4, 46, 48)
                if protocol == "TCP" or protocol == "UDP":
                    src_port, app_protocol = findPort(hex_pck, "src", dict_l5)
                    dst_port, app_protocol = findPort(hex_pck, "dst", dict_l5)
        else:
            if int(hex_pck[28:32], 16) == 0xFFFF:
                define_frame_type = 'IEEE 802.3 RAW'
            elif int(hex_pck[28:32], 16) == 0xAAAA:
                define_frame_type = 'IEEE 802.3 LLC & SNAP'
                # find correct protocol for IEEE 802.3 LLC & SNAP
                pid_value = findProtocol(hex_pck, dict_l3, 40, 44)
            else:
                define_frame_type = 'IEEE 802.3 LLC'
                sap_value = findSap(hex_pck, dict_l2)

        # sending data of packet to object
        pck_data = Packet(
            frame_number=frame_num,
            len_frame_pcap=len(pck),
            # +4 because of FCS
            len_frame_medium=max(64, len(pck) + 4),
            frame_type=define_frame_type,
            src_mac=':'.join(hex_pck[12:24][i:i + 2] for i in range(0, len(hex_pck[12:24]), 2)),
            dst_mac=':'.join(hex_pck[:12][i:i + 2] for i in range(0, len(hex_pck[:12]), 2)),
            ether_type=ether_type,
            sap=sap_value,
            pid=pid_value,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            app_protocol=app_protocol,
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
    listOfFrames('trace-25.pcap')
