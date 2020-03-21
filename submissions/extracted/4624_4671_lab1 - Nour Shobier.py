import enum
import os
import socket
import struct
import sys

class TftpProcessor(object):
    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        self.block_number = 1
        self.file_name = ''
        self.data_buffer = []
        self.packet_buffer = []
        pass

    def process_udp_packet(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")

        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        if packet_bytes[0:2] == self.TftpPacketType.ACK.value.to_bytes(2, 'big'):
            return ['ACK']

        elif packet_bytes[0:2] == self.TftpPacketType.ERROR.value.to_bytes(2, 'big'):
            error_message = packet_bytes[4:-1].decode("utf-8")
            print(error_message)
            exit(-1)

        elif packet_bytes[0:2] == self.TftpPacketType.DATA.value.to_bytes(2, 'big'):
            return [
                'DATA',
                # block number
                int.from_bytes(packet_bytes[2:4], 'big'),
                # data bytes
                packet_bytes[4:]
            ]

    def _do_some_logic(self, input_packet):
        if input_packet[0] == 'ACK':
            return self.build_data_packet()

        if input_packet[0] == 'DATA':
            return self.build_ack_packet(input_packet)

    def build_ack_packet(self, input_packet):
        block_number = input_packet[1]
        packet = struct.pack("!hh", self.TftpPacketType.ACK.value, block_number)
        with open(self.file_name, "ab") as file:
            file.write(input_packet[2])
        if len(input_packet[2]) < 512:
            exit(0)
        return packet

    def build_data_packet(self):
        if len(self.data_buffer) > 512:
            data = self.data_buffer[0:512]
            self.data_buffer = self.data_buffer[512:]
        else:
            data = self.data_buffer

        format_str = "!hh{}s".format(len(data))
        packet = struct.pack(format_str, self.TftpPacketType.DATA.value, self.block_number, data)
        self.block_number += 1
        return packet

    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

    def request_file(self, file_name):
        self.file_name = file_name

        format_str = "!h{}sb{}sb".format(len(file_name), len('octet'))

        packet = struct.pack(format_str,
                             self.TftpPacketType.RRQ.value,
                             file_name.encode("ascii"),
                             0,
                             "octet".encode("ascii"),
                             0)

        self.packet_buffer.append(packet)

    def upload_file(self, file_name):
        self.file_name = file_name

        bytes_list = open(file_name, 'rb').read()
        self.data_buffer = bytes_list

        format_str = "!h{}sb{}sb".format(len(file_name), len('octet'))

        packet = struct.pack(format_str,
                             self.TftpPacketType.WRQ.value,
                             file_name.encode("ascii"),
                             0,
                             "octet".encode("ascii"),
                             0)

        self.packet_buffer.append(packet)


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.settimeout(1)
    server_address = (address, 69)
    return udp_socket, server_address


def do_socket_logic(udp_socket, operation: str, server_address, file_name: str):
    tftp_processor = TftpProcessor()

    if operation == "push":
        tftp_processor.upload_file(file_name)
    else:
        tftp_processor.request_file(file_name)

    address = server_address

    try:
        while tftp_processor.has_pending_packets_to_be_sent():
            client_packet = tftp_processor.get_next_output_packet()

            udp_socket.sendto(client_packet, address)
            server_packet, address = udp_socket.recvfrom(4096)

            tftp_processor.process_udp_packet(server_packet, address)

    except socket.timeout:
        udp_socket.close()


def parse_user_input(address: str, operation: str, file_name: str = None):
    udp_socket, server_address = setup_sockets(address)

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        do_socket_logic(udp_socket, operation, server_address, file_name)
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        do_socket_logic(udp_socket, operation, server_address, file_name)
        pass


def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(f"[FATAL] The command-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def main():
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "push")
    file_name = get_arg(3, "test.txt")

    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
