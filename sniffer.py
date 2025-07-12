import socket
import struct
from datetime import datetime

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = connection.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = Ethernet_Frame(raw_data)
        print('\n   Ethernet Frame:')

        if eth_proto == 8:
            version, header_length, ttl, proto, src_ip, dst_ip, payload = IPv4_Packet(data)
            proto_name = get_protocol_name(proto)

            print(f'    - Version        : {version} (IPv{version})')
            print(f'    - Header Length  : {header_length}')
            print(f'    - TTL            : {ttl}')
            print(f'    - Protocol       : {proto} ({proto_name})')
            print(f'    - Destination MAC: {dest_mac}' )
            print(f'    - Destination IP : {dst_ip}')
            print(f'    - Source MAC     : {src_mac}')
            print(f'    - Source IP      : {src_ip}')
            print(f'    - Protocol       : {eth_proto}')  
            print(f'    - Timestamp      : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            print(f'    - Payload        :\n{hexdump(payload[:64])}')

def Ethernet_Frame(data):
    dest, src, proto = struct.unpack('!6s6sH', data[:14])
    return Get_MAC(dest), Get_MAC(src), socket.htons(proto), data[14:]

def Get_MAC(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def IPv4_Packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, IPv4(src), IPv4(target), data[header_length:]

def IPv4(addr):
    return '.'.join(map(str, addr))

def get_protocol_name(proto):
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP'
    }
    return protocols.get(proto, 'OTHER')

def hexdump(data, length=16):
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_chunk = ' '.join(f'{b:02x}' for b in chunk)
        ascii_chunk = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f'    {i:04x}  {hex_chunk:<48}  {ascii_chunk}')
    return '\n'.join(lines)

main()
