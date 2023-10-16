import ruamel.yaml
from collections import OrderedDict
from packet import Packet


def isValid(pck, protocol):
    if 'frame_type' in pck.kwargs and 'ether_type' in pck.kwargs:
        return pck.kwargs['frame_type'] == "Ethernet II" and pck.kwargs['ether_type'] == protocol


def parseHexData(hex_pck):
    hex_data = ""
    for char in hex_pck:
        if char != ' ' and char != '\n':
            hex_data += char

    return hex_data.upper().strip()


def areGroup(cmp_pck, other_pck):
    return (cmp_pck.kwargs['src_ip'] == other_pck.kwargs['src_ip']) and (cmp_pck.kwargs['dst_ip'] == other_pck.kwargs['dst_ip'])


def isAnswer(req_pck, rep_pck):
    ip_equality = (req_pck.kwargs['src_ip'] == rep_pck.kwargs['dst_ip']) and (req_pck.kwargs['dst_ip'] == rep_pck.kwargs['src_ip'])
    mac_equality = req_pck.kwargs['src_mac'] == rep_pck.kwargs['dst_mac']
    frame_similarity = req_pck.kwargs['frame_number'] == (rep_pck.kwargs['frame_number'] - 1)
    opcode_non_equality = req_pck.kwargs['arp_opcode'] != rep_pck.kwargs['arp_opcode']
    return ip_equality and mac_equality and frame_similarity and opcode_non_equality


def filterGroup(filter_list):
    groups_list = []

    # sort according to ip_addresses and ports
    for i in range(len(filter_list)):
        cmp_pck = filter_list[i]

        # Create a list to store communicating packets for cmp_pck
        communicating_pcks = [cmp_pck]

        # Iterate through the remaining packets
        for j in range(i + 1, len(filter_list)):
            other_pck = filter_list[j]

            # Check if the packets communicate
            if areGroup(cmp_pck, other_pck):
                communicating_pcks.append(other_pck)

        # Add the communicating packets to the result list without duplicates
        if not any(set(communicating_pcks).issubset(set(p)) for p in groups_list):
            groups_list.append(communicating_pcks)

    return groups_list


#

def connectGroups(request_list, reply_list):
    groups_list = []
    only_request_list = []
    only_reply_list = []

    for req_pcks in request_list:
        for rep_pcks in reply_list:
            for req_pck in req_pcks:
                for rep_pck in rep_pcks:
                    if isAnswer(req_pck, rep_pck):
                        # Create a list to store communicating packets
                        communicating_pcks = [req_pck, rep_pck]

                        # Check if this group already exists in groups_list
                        exists = False
                        for group in groups_list:
                            if set(communicating_pcks) == set(group):
                                exists = True
                                break

                        if not exists:
                            groups_list.append(communicating_pcks)

                    elif req_pck.kwargs['arp_opcode'] == "REQUEST":
                        only_request_list.append(req_pck)
                    elif rep_pck.kwargs['arp_opcode'] == "REPLY":
                        only_reply_list.append(rep_pck)

    return groups_list, only_request_list, only_reply_list


def checkList(c_list):
    if c_list:
        return c_list
    else:
        return None


def getProtocolList(packet_list, protocol, file_name):
    yaml_format = ruamel.yaml.YAML()
    request_list = []
    reply_list = []

    # sort according to protocol
    for pck in packet_list:
        if isValid(pck, protocol):

            hex_data = parseHexData(pck.kwargs['hexa_frame'])
            operation = int(hex_data[40:44])
            if operation == 1:
                comm = "REQUEST"
                request_list.append(pck)
            elif operation == 2:
                reply_list.append(pck)
                comm = "REPLY"

            kwargs_dict = OrderedDict()
            for key in pck.kwargs.keys():
                kwargs_dict[key] = pck.kwargs[key]
                if key == "ether_type":
                    kwargs_dict['arp_opcode'] = comm
            pck.kwargs = kwargs_dict

    filtered_request_list = filterGroup(request_list)
    filtered_reply_list = filterGroup(reply_list)

    connected_group, request_group, reply_group = connectGroups(filtered_request_list, filtered_reply_list)

    count_communications = 0
    comm_list = []
    for group in connected_group:
        count_communications += 1
        comm_data = Packet(
            number_comm=count_communications,
            packets=group
        )
        yaml_format.register_class(Packet)
        comm_list.append(comm_data)

    count_in_communications = 0
    in_comm_list = []
    for request in request_group:
        count_in_communications += 1
        comm_data = Packet(
            number_comm=count_in_communications,
            packets=request
        )
        yaml_format.register_class(Packet)
        in_comm_list.append(comm_data)

    for reply in reply_group:
        count_in_communications += 1
        comm_data = Packet(
            number_comm=count_in_communications,
            packets=request
        )
        yaml_format.register_class(Packet)
        in_comm_list.append(comm_data)

    header = {
        "name": "PKS2023/24",
        "pcap_name": file_name,
        "filter_name": protocol,
        "complete_comms": checkList(comm_list),
        "partial_comms": checkList(in_comm_list)
    }

    filtered_tcp_filter_header = {key: value for key, value in header.items() if value is not None}

    # write to the file all data
    with open('packets_' + protocol.lower() + '.yaml', 'w') as yaml_file:
        yaml_format.indent(offset=2, sequence=4)
        yaml_format.dump(filtered_tcp_filter_header, yaml_file)

    # replace '|-' to '|'
    with open('packets_' + protocol.lower() + '.yaml', 'r') as f:
        content = f.read()
    content = content.replace("|-\n", "|\n")
    with open('packets_' + protocol.lower() + '.yaml', 'w') as f:
        f.write(content)




