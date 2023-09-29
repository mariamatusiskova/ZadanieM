from ruamel import yaml
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
        return representer.represent_mapping(cls.yaml_tag, node.kwargs)

    @classmethod
    def from_yaml(cls, constructor, node):
        # return cls(*node.value.split('-'))
        data = constructor.construct_mapping(node, deep=True)
        return cls(**data)


def printPid(hex_pck):
    if int(hex_pck[40:44], 16) == 0x2000:
        print(f"pid: CDP")
    elif int(hex_pck[40:44], 16) == 0x2004:
        print(f"pid: DTP")
    elif int(hex_pck[40:44], 16) == 0x010B:
        print(f"pid: PVSTP+")
    elif int(hex_pck[40:44], 16) == 0x809B:
        print(f"pid: AppleTalk")


def printSap(hex_pck):
    if int(hex_pck[28:30], 16) == 0x42:
        print(f"sap: STP")
    elif int(hex_pck[28:30], 16) == 0xE0:
        print(f"sap: IPX")
    elif int(hex_pck[28:30], 16) == 0xF0:
        print(f"sap: NETBIOS")


def printHexData(hex_pck):
    hex_data = ""
    num_pairs = 0
    for i in range(0, len(hex_pck), 2):
        hex_data += hex_pck[i] + hex_pck[i + 1]
        hex_data += " "
        num_pairs += 1
        if num_pairs == 15:
            num_pairs = 0
            hex_data += "\n"

    hex_data = hex_data.upper()
    return hex_data


def listOfFrames():
    file = rdpcap('../vzorky_pcap_na_analyzu/trace-26.pcap')

    for frame_num, pck in enumerate(file, start=0):

        pck_data = Packet(
            frame_number=frame_num,
            len_frame_pcap=len(pck),
            # +4 because of FCS
            len_frame_medium=max(64, len(pck) + 4)
        )

        # transform code to raw data of wireshark
        # hexlify bytes and convert them to the string
        hex_pck = hexlify(bytes(pck)).decode('utf-8')

        sap = False
        pid = False

        if int(hex_pck[24:28], 16) >= 0x5DC:
            print(f"frame_type: Ethernet II")
        else:
            if int(hex_pck[28:32], 16) == 0xFFFF:
                print(f"frame_type: IEEE 802.3 RAW")
            elif int(hex_pck[28:32], 16) == 0xAAAA:
                print(f"frame_type: IEEE 802.3 LLC & SNAP")
                pid = True
            else:
                print(f"frame_type: IEEE 802.3 LLC")
                sap = True

        dst_addr = ':'.join(hex_pck[:12][i:i + 2] for i in range(0, len(hex_pck[:12]), 2))
        src_addr = ':'.join(hex_pck[12:24][i:i + 2] for i in range(0, len(hex_pck[12:24]), 2))

        print(f"src_mac: {src_addr}")
        print(f"dst_mac: {dst_addr}")

        if sap:
            printSap(hex_pck)
        elif pid:
            printPid(hex_pck)

        # print(f"hexa_frame: | \n{printHexData(hex_pck)}\n")
        # 'hexa_frame': ruamel.yaml.scalaring.LiteralScalarString(printHexData(hex_pck))


if __name__ == '__main__':
    listOfFrames()

    pck_data = Packet(
        frame_number=1,
        frame_type='ETHERNET II',
        src_mac='00:02:CF:AB:A2:4C',
        dst_mac='B4:B5:2F:74:CB:AE'
    )

    yaml = ruamel.yaml.YAML()
    yaml.register_class(Packet)
    yaml.dump([pck_data], sys.stdout)
