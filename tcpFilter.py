import ruamel.yaml
from packet import Packet


def areCommunicating(cmp_pck, other_pck):
    ip_equality = (cmp_pck.kwargs['src_ip'] == other_pck.kwargs['src_ip'] or cmp_pck.kwargs['src_ip'] ==
                   other_pck.kwargs['dst_ip']) and (
                              cmp_pck.kwargs['dst_ip'] == other_pck.kwargs['src_ip'] or cmp_pck.kwargs['dst_ip'] ==
                              other_pck.kwargs['dst_ip'])
    port_equality = (cmp_pck.kwargs['src_port'] == other_pck.kwargs['src_port'] or cmp_pck.kwargs['src_port'] ==
                     other_pck.kwargs['dst_port']) and (
                                cmp_pck.kwargs['dst_port'] == other_pck.kwargs['src_port'] or cmp_pck.kwargs[
                            'dst_port'] == other_pck.kwargs['dst_port'])
    return ip_equality and port_equality


def isValid(pck, protocol):
    if 'frame_type' in pck.kwargs and 'ether_type' in pck.kwargs and 'protocol' in pck.kwargs and 'app_protocol' in pck.kwargs:
        return pck.kwargs['frame_type'] == "Ethernet II" and pck.kwargs['ether_type'] == "IPv4" and pck.kwargs[
            'protocol'] == "TCP" and pck.kwargs['app_protocol'] == protocol


def isComplete(open_num, finish_num, group_list, first_incomplete):
    final_group_list = []

    if open_num <= -1 and finish_num <= -1:
        return [], "empty"
    elif (open_num >= -1 and finish_num <= -1) or (open_num <= -1 and finish_num >= -1):
        first_incomplete += 1

        if first_incomplete == 1:
            for pck in group_list:
                frame_number = pck.kwargs['frame_number']
                if -1 <= open_num and frame_number >= open_num and finish_num <= -1:
                    final_group_list.append(pck.kwargs)
                elif finish_num >= -1 and frame_number <= finish_num and open_num <= -1:
                    final_group_list.append(pck.kwargs)

        return final_group_list, "incomplete"

    for pck in group_list:
        frame_number = pck.kwargs['frame_number']
        if open_num <= frame_number <= finish_num:
            final_group_list.append(pck.kwargs)

    return final_group_list, "complete"



def checkFinishFlags(binary_data, comm_list, frame_num, counter):
    if comm_list:
        flag_list = comm_list.copy()
    else:
        flag_list = []

    fin = "FIN"
    syn = "SYN"
    rst = "RST"
    psh = "PSH"
    ack = "ACK"
    count_flags = 0
    finishing_list = []

    # FIN
    if int(binary_data[-1]) == 1:
        flag_list.append(fin)
        count_flags += 1
    # SYN
    elif int(binary_data[-2]) == 1:
        flag_list.append(syn)
        count_flags += 1
    # RST
    elif int(binary_data[-3]) == 1:
        flag_list.append(rst)
        count_flags += 1
    # PSH
    elif int(binary_data[-4]) == 1:
        count_flags += 1
    # ACK
    elif int(binary_data[-5]) == 1:
        flag_list.append(ack)
        count_flags += 1

    if count_flags > 0 and flag_list and (flag_list[0] == "FIN" or rst in flag_list):
        finishing_list = flag_list.copy()
        counter += 1

    if counter == 4 and (len(finishing_list) == 6 and finishing_list[0:6] == ["FIN", "ACK", "ACK", "FIN", "ACK", "ACK"] or finishing_list[0:6] == ["FIN", "ACK", "FIN", "ACK", "ACK", "ACK"]) or rst in finishing_list:
        pck_num = frame_num
        counter = 0
        return pck_num, finishing_list.clear(), counter
    elif counter == 3 and (len(finishing_list) == 5 and finishing_list[0:5] == ["FIN", "ACK", "ACK", "RST", "ACK"]):
        pck_num = frame_num - counter
        counter = 0
        return pck_num, finishing_list.clear(), counter
    elif (len(finishing_list) == 6 and (finishing_list[0:6] != ["FIN", "ACK", "ACK", "FIN", "ACK", "ACK"] or finishing_list[0:6] != ["FIN", "ACK", "FIN", "ACK", "ACK", "ACK"])) or counter == 3 and (len(finishing_list) == 5 and finishing_list[0:5] != ["FIN", "ACK", "ACK", "RST", "ACK"]):
        counter = 0
        return -1, finishing_list.clear(), counter
    else:
        return -1, finishing_list, counter


def checkStartFlags(binary_data, comm_list, frame_num, counter):
    if comm_list:
        flag_list = comm_list.copy()
    else:
        flag_list = []

    starting_list = []
    fin = "FIN"
    syn = "SYN"
    rst = "RST"
    psh = "PSH"
    ack = "ACK"
    count_flags = 0

    # FIN
    if int(binary_data[-1]) == 1:
        flag_list.append(fin)
        count_flags += 1
    # SYN
    elif int(binary_data[-2]) == 1:
        flag_list.append(syn)
        count_flags += 1
    # RST
    elif int(binary_data[-3]) == 1:
        count_flags += 1
    # PSH
    elif int(binary_data[-4]) == 1:
        count_flags += 1
    # ACK
    elif int(binary_data[-5]) == 1:
        flag_list.append(ack)
        count_flags += 1

    if count_flags > 0 and flag_list and (flag_list[0] == "SYN"):
        starting_list = flag_list.copy()
        counter += 1

    if (counter == 3 or counter == 4) and (len(starting_list) == 4 and starting_list[0:4] == ["SYN", "SYN", "ACK", "ACK"]):
        if counter == 3 or counter == 4:
            pck_num = frame_num - counter
        else:
            pck_num = frame_num
        counter = 0
        return pck_num, starting_list.clear(), counter
    elif len(flag_list) == 4 and flag_list[0:4] != ["SYN", "SYN", "ACK", "ACK"]:
        counter = 0
        return -1, starting_list.clear(), counter
    else:
        return -1, starting_list, counter


def parseHexData(hex_pck):
    hex_data = ""
    for char in hex_pck:
        if char != ' ' and char != '\n':
            hex_data += char

    return hex_data.upper().strip()


def checkList(c_list):
    if c_list:
        return c_list
    else:
        return None


def getProtocolList(packet_list, protocol, file_name):
    yaml_format = ruamel.yaml.YAML()
    groups_list = []
    rough_filter_pck_list = []

    # sort according to protocol
    for pck in packet_list:
        if isValid(pck, protocol):
            rough_filter_pck_list.append(pck)

    # sort according to ip_addresses and ports
    for i in range(len(rough_filter_pck_list)):
        cmp_pck = rough_filter_pck_list[i]

        # Create a list to store communicating packets for cmp_pck
        communicating_pcks = [cmp_pck]

        # Iterate through the remaining packets
        for j in range(i + 1, len(rough_filter_pck_list)):
            other_pck = rough_filter_pck_list[j]

            # Check if the packets communicate
            if areCommunicating(cmp_pck, other_pck):
                communicating_pcks.append(other_pck)

        # Add the communicating packets to the result list without duplicates
        if not any(set(communicating_pcks).issubset(set(p)) for p in groups_list):
            groups_list.append(communicating_pcks)

    # sort according to complete and incomplete communications
    open_comm = 0
    finish_comm = 0
    counter_start = 0
    counter_finish = 0
    start = []
    end = []
    count_incomplete = 0
    comm_list = []
    in_comm_list = []
    count_communications = 0
    for group in groups_list:
        src_comm = None
        dst_comm = None
        count_packets = 0
        for packet in group:
            count_packets += 1
            hex_pck = parseHexData(packet.kwargs['hexa_frame'])
            bin_shift = (int(hex_pck[29], 16) * 4 * 2) - (20 * 2)
            binary_data = bin(int(hex_pck[93 + bin_shift: 96 + bin_shift], 16))

            if count_packets == 1:
                src_comm = packet.kwargs['src_ip']
                dst_comm = packet.kwargs['dst_ip']

            open_comm, start, counter_start = checkStartFlags(binary_data, start, packet.kwargs['frame_number'], counter_start)
            finish_comm, end, counter_finish = checkFinishFlags(binary_data, end, packet.kwargs['frame_number'], counter_finish)

        final_group_list, status = isComplete(open_comm, finish_comm, group, count_incomplete)

        if final_group_list and status == "complete":
            count_communications += 1

            comm_data = Packet(
                number_comm=count_communications,
                src_comm=src_comm,
                dst_comm=dst_comm,
                packets=final_group_list
            )

            yaml_format.register_class(Packet)
            comm_list.append(comm_data)
        elif final_group_list and status == "incomplete":
            count_incomplete += 1
            if count_incomplete == 1:
                comm_data = Packet(
                    number_comm=count_incomplete,
                    packets=final_group_list
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