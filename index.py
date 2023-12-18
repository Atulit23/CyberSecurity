import scapy.all as scapy
import subprocess
import time
import socket

def get_ip():
    try:
        host_name = socket.gethostname()
        ip_address = socket.gethostbyname(host_name)
        return ip_address
    except Exception as e:
        print(f"Error: {e}")
        return None


current_ip = get_ip()
last_packet_time = [time.time()]
src_size = [0]
dst_size = [0]
packet_dict = {'sent': {}, 'received': {}}

def get_protocol_name(protocol_num):
    protocol_names = {
        17: 'UDP',
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        1: 'ICMP',
        2: 'IGMP',
        89: 'OSPF',
        112: 'VRRP',
        115: 'L2TP',
        136: 'UDPLite',
        137: 'SCTP',
        138: 'FC',
        139: 'RARP',
        141: 'MPLS',
        142: 'MANET',
        143: 'HIP',
        253: 'Use for experimentation and testing',
        254: 'Use for experimentation and testing',
        255: 'Reserved',
        0: 'HOPOPT',
        43: 'Routing Header for IPv6',
        44: 'Fragment Header for IPv6',
        60: 'Destination Options for IPv6',
        115: 'L2TP',
        118: 'STP',
        151: 'MPRTP',
        177: 'ISO-IP',
        213: 'GW-IP',
        224: 'MHRP',
        255: 'Reserved',
        103: 'PIM',
        108: 'Compact Routing',
        112: 'VRRP',
        133: 'PHOENIX',
        140: 'HIP',
        142: 'Shim6',
        211: 'SCPS',
        222: 'TP++',
        254: 'Experimentation and testing',
        255: 'Reserved',
        103: 'PIM',
        108: 'Compact Routing',
        112: 'VRRP',
        133: 'PHOENIX',
        140: 'HIP'
    }
    return protocol_names[protocol_num]

def update_packet_dict(origin, key, detail):
    sentKeys = list(packet_dict['sent'].keys())
    receivedKeys = list(packet_dict['received'].keys())

    if origin == 'src':
        if key in sentKeys:
            packet_dict['sent'][key]['count'] = packet_dict['sent'][key]['count'] + 1
            packet_dict['sent'][key]['sentTo'] = detail
        else:
            packet_dict['sent'].setdefault(key, {'count': 1, 'sentTo': detail})
    else:
        if key in receivedKeys:
            packet_dict['received'][key]['count'] = packet_dict['received'][key]['count'] + 1
            packet_dict['received'][key]['sentFrom'] = detail
        else:
            packet_dict['received'].setdefault(key, {'count': 1, 'sentFrom': detail})

def packet_callback(packet):
    current_time = time.time()
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        # print(packet[scapy.IP])

        if current_ip:
            if src_ip == current_ip:
                src_size[0] = len(packet)
                update_packet_dict('src', src_ip, dst_ip) #sent packets
            elif dst_ip == current_ip:
                dst_size[0]= len(packet)
                update_packet_dict('dst', src_ip, dst_ip) #recieved packets
        else:
            print("Unable to retrieve the IP address.")

        time_elasped = current_time - last_packet_time[0]

        print(f"Packet: {src_ip} -> {dst_ip}, Source Size: {src_size[0]} bytes, Sent packets: {packet_dict['sent']}, Received packets: {packet_dict['received']}, Time Elasped: {time_elasped}, Protocol: {get_protocol_name(protocol)}, Destination Size: {dst_size[0]} bytes")

        last_packet_time[0] = current_time


def sniff_packets():
    scapy.sniff(iface=network_interface, store=False, prn=packet_callback, count=packet_count, promisc=True)

network_interface = "Wi-Fi"
packet_count = 0 # count -> 0 for conitunous packet collection

sniff_packets(network_interface, packet_count)