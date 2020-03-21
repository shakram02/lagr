import enum
import os
import socket
import sys
import struct
import math

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.settimeout(5)


class TftpProcessor(object):
    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        self.packet_buffer = []
        self.file_name = ""
        self.content = bytearray
        pass

    def process_udp_packet(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        parsed_package = bytearray()
        op_code = [packet_bytes[0], packet_bytes[1]]
        if op_code[1] == self.TftpPacketType.DATA.value:
            parsed_package = [self.TftpPacketType.DATA.name, int.from_bytes(packet_bytes[2:3], byteorder='big'),
                              int.from_bytes(packet_bytes[3:4], byteorder='big'),
                              packet_bytes[4:]]
        elif op_code[1] == self.TftpPacketType.ACK.value:
            parsed_package = [self.TftpPacketType.ACK.name, int.from_bytes(packet_bytes[2:3], byteorder='big'),
                              int.from_bytes(packet_bytes[3:4], byteorder='big')]
        elif op_code[1] == self.TftpPacketType.ERROR.value:
            parsed_package = [self.TftpPacketType.ERROR.name, int.from_bytes(packet_bytes[2:4], byteorder='big'),
                              packet_bytes[4:]]
        else:
            print(" UNDEFINED OP-CODE ")
            client_socket.close()
            exit()
        return parsed_package

    pass

    def send_file(self, block_number1, block_number2):
        block_number = int(str(block_number1) + str(block_number2)) + 1
        if block_number > math.ceil(len(self.content) / 512):
            print("Done Uploading.")
            client_socket.close()
            exit()
        chunks = self.content[(block_number - 1) * 512:block_number * 512]
        out_packet = struct.pack("!HH{}s".format(len(chunks)), 3, block_number, chunks)
        return out_packet

    pass

    def receive_file(self, data):
        file = open(self.file_name, "a")
        file.write(data.decode("latin-1").replace("\n", ""))
        file.close()
        if len(data) < 512:
            print("Done Downloading.")
            client_socket.close()
            exit()

    pass

    def _do_some_logic(self, input_packet):
        out_packet = bytearray()
        if input_packet[0] == self.TftpPacketType.DATA.name:
            block_number = int(str(input_packet[1]) + str(input_packet[2]))
            out_packet = struct.pack("!HH", 4, block_number)
            TftpProcessor.receive_file(self, input_packet[3])
        elif input_packet[0] == self.TftpPacketType.ACK.name:
            out_packet = TftpProcessor.send_file(self, input_packet[1], input_packet[2])
        elif input_packet[0] == self.TftpPacketType.ERROR.name:
            message = ["Not defined, see error message (if any).", "File not found.", "Access violation.",
                       "Disk full or allocation exceeded.", "Illegal TFTP operation.", "Unknown transfer ID.",
                       "File already exists.", "No such user."]
            print(message[input_packet[1]])
            client_socket.close()
            exit()

        return out_packet

    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        self.file_name = file_path_on_server
        if os.path.exists(file_path_on_server):
            request_file = struct.pack("!HH{}sB".format(len("File already exists.")), 5, 6, "File already exists.".encode('ascii'), 0)
        else:
            request_file = bytearray([0, 1])
            request_file.extend(file_path_on_server.encode('ascii'))
            request_file.append(0)
            request_file.extend('octet'.encode('ascii'))
            request_file.append(0)
            print(f"Request {request_file}")
        return request_file

    pass

    def upload_file(self, file_path_on_server):
        self.file_name = file_path_on_server
        if not os.path.isfile(self.file_name):
            upload_file = struct.pack("!HH{}sB".format(len("File not found.")), 5, 1, "File not found.".encode('ascii'), 0)
        else:
            print("File exists")
            with open(self.file_name, 'rb') as fp:
                self.content = bytearray(os.path.getsize(self.file_name))
                fp.readinto(self.content)
            fp.close()
            upload_file = bytearray([0, 2])
            upload_file.extend(file_path_on_server.encode('ascii'))
            upload_file.append(0)
            upload_file.extend('octet'.encode('ascii'))
            upload_file.append(0)
            print(f"Request {upload_file}")
        return upload_file

    pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def parse_user_input(address, operation, file_name=None):
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        pass


def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def main():
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)
    packet = bytearray
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")
    tftp_obj = TftpProcessor()
    server_address = (ip_address, 69)
    if operation == "pull":
        packet = TftpProcessor.request_file(tftp_obj, file_name)
    elif operation == "push":
        packet = TftpProcessor.upload_file(tftp_obj, file_name)
    parse_user_input(ip_address, operation, file_name)
    print(f"Sending a packet {packet} to {server_address}")
    client_socket.sendto(packet, server_address)
    server_packet, server_address = client_socket.recvfrom(516)
    TftpProcessor.process_udp_packet(tftp_obj, server_packet, server_address)
    while True:
        if not TftpProcessor.has_pending_packets_to_be_sent(tftp_obj):
            print("Done")
            client_socket.close()
            exit()
        packet = TftpProcessor.get_next_output_packet(tftp_obj)
        print(f"Sending a packet to {server_address}")
        client_socket.sendto(packet, server_address)
        server_packet, server_address = client_socket.recvfrom(516)
        TftpProcessor.process_udp_packet(tftp_obj, server_packet, server_address)


if __name__ == "__main__":
    main()
