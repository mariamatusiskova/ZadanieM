import ruamel.yaml


def isValid(pck, protocol):
    if 'frame_type' in pck.kwargs and 'ether_type' in pck.kwargs and 'protocol' in pck.kwargs and 'app_protocol' in pck.kwargs:
        return pck.kwargs['frame_type'] == "Ethernet II" and pck.kwargs['ether_type'] == "IPv4" and pck.kwargs[
            'protocol'] == "UDP" and pck.kwargs['app_protocol'] == protocol

def getProtocolListDNS(packet_list, protocol, file_name):
    yaml_format = ruamel.yaml.YAML()
    rough_filter_pck_list = []
    count_frames = 0

    # sort according to protocol
    for pck in packet_list:
        if isValid(pck, protocol):
            count_frames += 1
            rough_filter_pck_list.append(pck)


    header = {
        "name": "PKS2023/24",
        "pcap_name": file_name,
        "packets": rough_filter_pck_list,
        "number_frames": count_frames
    }

    # write to the file all data
    with open('packets_' + protocol.lower() + '.yaml', 'w') as yaml_file:
        yaml_format.indent(offset=2, sequence=4)
        yaml_format.dump(header, yaml_file)

    # replace '|-' to '|'
    with open('packets_' + protocol.lower() + '.yaml', 'r') as f:
        content = f.read()
    content = content.replace("|-\n", "|\n")
    with open('packets_' + protocol.lower() + '.yaml', 'w') as f:
        f.write(content)




