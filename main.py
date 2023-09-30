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

    #kwargs for various length of properties
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


######################################## change
# find ether type
def findUDPProtocol(hex_pck):
    if int(hex_pck[24:28], 16) == 37:
        return 'TIME'
    elif int(hex_pck[24:28], 16) == 53:
        return 'DNS'
    elif int(hex_pck[24:28], 16) == 67 or int(hex_pck[24:28], 16) == 68:
        return 'DHCP'
    elif int(hex_pck[24:28], 16) == 69:
        return 'TFTP'
    elif int(hex_pck[24:28], 16) == 80:
        return 'HTTP'
    elif int(hex_pck[24:28], 16) == 137:
        return 'NETBIOS-NS'
    elif int(hex_pck[24:28], 16) == 138:
        return 'NETBIOS-DGM'
    elif int(hex_pck[24:28], 16) == 161:
        return 'SNMP'
    elif int(hex_pck[24:28], 16) == 162:
        return 'SNMP-TRAP'
    elif int(hex_pck[24:28], 16) == 443:
        return 'HTTPS'
    elif int(hex_pck[24:28], 16) == 514:
        return 'SYSLOG'
    elif int(hex_pck[24:28], 16) == 520:
        return 'RIP'
    elif int(hex_pck[24:28], 16) == 1900:
        return 'SSDP'
    elif int(hex_pck[24:28], 16) == 5353:
        return 'MDNS'
    elif int(hex_pck[24:28], 16) == 17500:
        return 'DB-LSP-DISC'
    elif int(hex_pck[24:28], 16) == 33434:
        return 'TRACEROUTE'


######################################## change
# find ether type
def findTCPProtocol(hex_pck):
    if int(hex_pck[24:28], 16) == 20:
        return 'FTP-DATA'
    elif int(hex_pck[24:28], 16) == 21:
        return 'FTP-CONTROL'
    elif int(hex_pck[24:28], 16) == 22:
        return 'SSH'
    elif int(hex_pck[24:28], 16) == 23:
        return 'TELNET'
    elif int(hex_pck[24:28], 16) == 25:
        return 'SMTP'
    elif int(hex_pck[24:28], 16) == 53:
        return 'DNS'
    elif int(hex_pck[24:28], 16) == 80:
        return 'HTTP'
    elif int(hex_pck[24:28], 16) == 110:
        return 'POP3'
    elif int(hex_pck[24:28], 16) == 119:
        return 'NNTP'
    elif int(hex_pck[24:28], 16) == 137:
        return 'NETBIOS-NS'
    elif int(hex_pck[24:28], 16) == 139:
        return 'NETBIOS-SSN'
    elif int(hex_pck[24:28], 16) == 143:
        return 'IMAP'
    elif int(hex_pck[24:28], 16) == 162:
        return 'SNMP-TRAP'
    elif int(hex_pck[24:28], 16) == 179:
        return 'BGP'
    elif int(hex_pck[24:28], 16) == 389:
        return 'LDAP'
    elif int(hex_pck[24:28], 16) == 443:
        return 'HTTPS'
    elif int(hex_pck[24:28], 16) == 514:
        return 'SYSLOG'
    elif int(hex_pck[24:28], 16) == 17500:
        return 'DB-LSP-DISC'



######################################## change
# find ether type
def findIPv4Protocol(hex_pck):
    if int(hex_pck[24:28], 16) == 0x01:
        return 'ICMP'
    elif int(hex_pck[24:28], 16) == 0x02:
        return 'IGMP'
    elif int(hex_pck[24:28], 16) == 0x06:
        return 'TCP'
    elif int(hex_pck[24:28], 16) == 0x11:
        return 'UDP'
    elif int(hex_pck[24:28], 16) == 0x67:
        return 'PIM'


########################################
# find ether type
def findEtherTypeEthernet(hex_pck):
    if int(hex_pck[24:28], 16) == 0x0800:
        return 'IPv4'
    elif int(hex_pck[24:28], 16) == 0x0806:
        return 'ARP'
    elif int(hex_pck[24:28], 16) == 0x88CC:
        return 'LLDP'
    elif int(hex_pck[24:28], 16) == 0x86DD:
        return 'IPv6'
    elif int(hex_pck[24:28], 16) == 0x9000:
        return 'ECTP'


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


# find correct protocol IEEE 802.3 LLC
def findSap(hex_pck):
    if int(hex_pck[28:30], 16) == 0x42:
        return 'STP'
    elif int(hex_pck[28:30], 16) == 0xE0:
        return 'IPX'
    elif int(hex_pck[28:30], 16) == 0xF0:
        return 'NETBIOS'


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


# list frames into yaml, main logic
def listOfFrames(file_name):
    file = rdpcap('../vzorky_pcap_na_analyzu/' + file_name)

    pck_list = []
    yaml_format = ruamel.yaml.YAML()

    for frame_num, pck in enumerate(file, start=0):

        # transform code to raw data of wireshark
        # hexlify bytes and convert them to the string
        hex_pck = hexlify(bytes(pck)).decode('utf-8')

        sap_value = None
        pid_value = None

        # beginning index normal, last one + 1
        if int(hex_pck[24:28], 16) >= 0x5DC:
            define_frame_type = 'Ethernet II'
            define_ether_type = None
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
            ether_type=None,
            sap=sap_value,
            pid=pid_value,
            hexa_frame=scalarstring.PreservedScalarString(printHexData(hex_pck))
        )

        yaml_format.register_class(Packet)
        pck_list.append(pck_data)

    header = {
        "name": "PKS2023/24",
        "pcap_name": file_name,
        "packets": pck_list
    }

    with open('yaml_file.yaml', 'w') as yaml_file:
        yaml_format.indent(offset=2, sequence=4)
        yaml_format.dump(header, yaml_file)

    with open('yaml_file.yaml', 'r') as f:
        content = f.read()
    content = content.replace("|-\n", "|\n")
    with open('yaml_file.yaml', 'w') as f:
        f.write(content)


if __name__ == '__main__':
    listOfFrames('trace-27.pcap')
