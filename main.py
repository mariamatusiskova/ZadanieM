from ruamel import yaml
from ruamel.yaml import scalarstring
from scapy.all import *
from binascii import hexlify
import ruamel.yaml


# yaml format
# https://yaml.readthedocs.io/en/latest/dumpcls.html
class Packet:
    yaml_tag = u'tag:yaml.org,2002:map'

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    @classmethod
    def to_yaml(cls, representer, node):
        for key, value in list(node.kwargs.items()):
            if value is None:
                node.kwargs.pop(key)
        return representer.represent_mapping(cls.yaml_tag, node.kwargs)

    @classmethod
    def from_yaml(cls, constructor, node):
        # return cls(*node.value.split('-'))
        data = constructor.construct_mapping(node, deep=True)
        return cls(**data)


def findPid(hex_pck):
    if int(hex_pck[40:44], 16) == 0x2000:
        return 'CDP'
    elif int(hex_pck[40:44], 16) == 0x2004:
        return 'DTP'
    elif int(hex_pck[40:44], 16) == 0x010B:
        return 'PVSTP+'
    elif int(hex_pck[40:44], 16) == 0x809B:
        return 'AppleTalk'


def findSap(hex_pck):
    if int(hex_pck[28:30], 16) == 0x42:
        return 'STP'
    elif int(hex_pck[28:30], 16) == 0xE0:
        return 'IPX'
    elif int(hex_pck[28:30], 16) == 0xF0:
        return 'NETBIOS'


def printHexData(hex_pck):
    hex_data = ""
    num_pairs = 0
    for i in range(0, len(hex_pck), 2):
        hex_data += hex_pck[i] + hex_pck[i + 1]
        num_pairs += 1
        if num_pairs < 15:
            hex_data += " "
        if num_pairs == 15:
            num_pairs = 0
            hex_data += "\n"


    return hex_data.upper()


def listOfFrames():
    file = rdpcap('../vzorky_pcap_na_analyzu/trace-26.pcap')

    # Initialize the begin dictionary
    begin = {
        "name": "PKS2023/24",
        "pcap_name": "eth-1.pcap",
        "packets": []
    }

    # Open the YAML file in write mode
    with open('yaml_file.yml', 'w') as yaml_file:
        # Write the begin dictionary at the beginning of the file
        yaml = ruamel.yaml.YAML()
        yaml.dump(begin, yaml_file)

    with open('yaml_file.yml', 'a') as yaml_file:

        for frame_num, pck in enumerate(file, start=0):

            # transform code to raw data of wireshark
            # hexlify bytes and convert them to the string
            hex_pck = hexlify(bytes(pck)).decode('utf-8')

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

            # yaml_format = ruamel.yaml.YAML()
            # yaml_format.register_class(Packet)
            # yaml_format.dump([pck_data], yaml_file)
            yaml_format = ruamel.yaml.YAML()
            yaml_format.register_class(Packet)
            begin["packets"].append(pck_data)

            # Rewrite the entire YAML file with the updated begin dictionary
            yaml_format.dump(begin, yaml_file)



    # with open(r'yaml_file.yml', 'w') as yaml_file:
    #     yaml.dump(begin, yaml_file, default_flow_style=False)
    #     #yaml_format.dump([pck_data], sys.stdout)

        # print(f"hexa_frame: | \n{printHexData(hex_pck)}\n")
        # 'hexa_frame': ruamel.yaml.scalaring.LiteralScalarString(printHexData(hex_pck))


if __name__ == '__main__':
    listOfFrames()
