import socket
import struct
import os
import re
import sys
import enum

class TftpProcessor(object):
    class TftpPacketType(enum.Enum):

        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5


    def __init__(self):

        self.packet_buffer = []
        self.data_blocks = []
        self.write_blocks = []
        self.count = 1
        self.server_error_msg = {

            0: "Not defined, see error message (if any).",
            1: "File not found.",
            2: "Access violation.",
            3: "Disk full or allocation exceeded.",
            4: "Illegal TFTP operation.",
            5: "Unknown transfer ID.",
            6: "File already exists.",
            7: "No such user."
        }


    def byte_block(self, block):
        packed = struct.pack('!{0}s'.format(len(block)), block.encode("ASCII"))
        return list(packed)


    def acknowledge_packet(self, op_block_no):
        ack = bytearray(op_block_no)
        ack[0] = 0
        ack[1] = 4
        return ack


    def format_packet_data(self, block, block_number):
        data_req = bytearray()
        data_req.append(0)
        data_req.append(3)
        b = struct.pack(">H", block_number)
        c = list(b)
        data_req.append(c[0])
        data_req.append(c[1])
        for i in self.byte_block(block):
            data_req.append(i)
        return data_req


    def process_udp_packet(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")
        out_packet = self._parse_udp_packet(packet_data)
        self.packet_buffer.append(out_packet)


    def _parse_udp_packet(self, packet_bytes):
        opcode = int.from_bytes(packet_bytes[:2], byteorder='big')
        if opcode == self.TftpPacketType.DATA.value:
            ackn = self.acknowledge_packet(packet_bytes[0:4])
            return ackn
        elif opcode == self.TftpPacketType.ACK.value:
            data_packet = self.format_packet_data(self.data_blocks[self.count - 1], self.count)
            return data_packet
        else:
            error_code = int.from_bytes(packet_bytes[2:4], byteorder='big')
            print(self.server_error_msg[error_code])
            exit(-1)


    def get_next_output_packet(self):
        return self.packet_buffer.pop(0)


    def has_pending_packets_to_be_sent(self):
        return len(self.packet_buffer) != 0


    def write_file(self, file_path_on_server):
        f_write = open(file_path_on_server, "wb")
        for i in self.write_blocks:
            f_write.write(i)
        f_write.close()


    def read_file(self, file_path_on_server):
        f = open(file_path_on_server, "r")
        f_contents = f.read(512)
        while len(f_contents) > 0:
            self.data_blocks.append(f_contents)
            f_contents = f.read(512)
        f.close()


    def request_file(self, file_path_on_server):

        request = bytearray()
        request.append(0)
        request.append(1)

        f_name = bytearray(file_path_on_server.encode("ASCII"))
        request += f_name
        request.append(0)

        mode = bytearray("octet".encode("ASCII"))
        request += mode
        request.append(0)
        self.packet_buffer.append(request)


    def upload_file(self, file_path_on_server):

        request = bytearray()
        request.append(0)
        request.append(2)

        f_name = bytearray(file_path_on_server.encode("ASCII"))
        request += f_name
        request.append(0)

        mode = bytearray("octet".encode("ASCII"))
        request += mode
        request.append(0)
        self.packet_buffer.append(request)


def check_file_name():
    script_name = os.path.basename(__file__)
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
        exit(-1)


def setup_socket(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)
    return sock, server_address


def parse_user_input(address, operation, file_name=None):
    socket, server_address = setup_socket(address)
    tftp_object = TftpProcessor()

    if operation == "push":
        tftp_object.read_file(file_name)
        tftp_object.upload_file(file_name)
        write_request = tftp_object.get_next_output_packet()
        sent = socket.sendto(write_request, server_address)
        print("waiting for response")
        data, server = socket.recvfrom(4096)
        print("connection successfully...")

        while True:
            tftp_object.process_udp_packet(data, server)
            if tftp_object.has_pending_packets_to_be_sent():
                data_packet = tftp_object.get_next_output_packet()
                size = len(data_packet)
                socket.sendto(data_packet, server)
                print("waiting for acknowledge for the sending block...")
                data, server = socket.recvfrom(4096)
                print("upload successfully...")
                tftp_object.count = tftp_object.count + 1  # block_no
                if size < 516:
                    break
            else:
                break

    elif operation == "pull":
        tftp_object.request_file(file_name)
        read_request = tftp_object.get_next_output_packet()
        sent = socket.sendto(read_request, server_address)

        while True:
            print("waiting for response")
            data, server = socket.recvfrom(4096)
            print("connection successfully...")
            tftp_object.process_udp_packet(data, server)
            if tftp_object.has_pending_packets_to_be_sent():
                ack_packet = tftp_object.get_next_output_packet()
                socket.sendto(ack_packet, server)
                tftp_object.write_blocks.append(data[4:])
                if len(data) < 516:
                    break
            else:
                break
        if len(tftp_object.write_blocks) != 0:
            tftp_object.write_file(file_name)
    socket.close()


def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def main():
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()