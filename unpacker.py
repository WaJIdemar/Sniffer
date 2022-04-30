import socket
import struct


class Unpacker:
    def ethernet_head(self, raw_data: bytes) -> tuple[str, str, int, bytes]:
        """Getting ethernet header"""
        destination, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
        destination_mac = self.get_mac_addr(destination)
        src_mac = self.get_mac_addr(src)
        proto = socket.htons(prototype)
        data = raw_data[14:]
        return destination_mac, src_mac, proto, data

    def ipv4_head(self, raw_data: bytes) -> tuple[
        int, int, int, int, str, str, bytes]:
        """Getting ipv4 header"""
        version_header_length = raw_data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',
                                                raw_data[:20])
        src = self.get_ip(src)
        target = self.get_ip(target)
        data = raw_data[header_length:]
        return version, header_length, ttl, proto, src, target, data

    def get_ip(self, addr: bytes) -> str:
        """Converting an ip address from bytes to a string"""
        return '.'.join(map(str, addr))

    def get_mac_addr(self, bytes_addr: bytes) -> str:
        """Converting an MAC address from bytes to a string"""
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def tcp_head(self, raw_data: bytes) -> tuple[
        int, int, int, int, int, int, int, int, int, int, bytes]:
        """Getting tcp header"""
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = \
            struct.unpack('! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        data = raw_data[offset:]
        return src_port, dest_port, sequence, acknowledgment, flag_urg, \
               flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

    def icmp_packet(self, raw_data: bytes) -> tuple[int, int, int, bytes]:
        """Icmp packet parser"""
        icmp_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
        return icmp_type, code, checksum, raw_data[4:]

    def udp_head(self, raw_data: bytes) -> tuple[int, int, int, bytes]:
        """Getting udp header"""
        src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
        return src_port, dest_port, size, raw_data[8:]

    def parsing_http(self, raw_data: bytes):
        data = raw_data.decode('utf-8')
