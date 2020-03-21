import struct
import sys
import os
import enum
import socket

UPLOAD = 1
DOWNLOAD = 0
FILENAME = "filename"
BLOCKNO = "block"
OPCODE = "opcode"
ERRORCODE = "errorcode"
ERRMSG = "errmsg"
DATA = "data"

tftp_error_messages = [
    "Not defined, see error message (if any).",
    "File not found.",
    "Access violation.",
    "Disk full or allocation exceeded.",
    "Illegal TFTP operation.",
    "Unknown transfer ID.",
    "File already exists.",
    "No such user.",
]


def make_data_packet(bytearr, i):
    return struct.pack(f'!HH{len(bytearr)}s', TftpPacketType.DATA.value, i, bytearr)


class Packer:

    def __init__(self, byte_segmented_file):
        self.byte_segmented_file = byte_segmented_file

    def pack(self):
        packets = []
        i = 1
        for datapack in self.byte_segmented_file:
            packets.append(struct.pack(f'!HH{len(datapack)}s', TftpPacketType.DATA.value, i, datapack))
            i += 1
        if len(self.byte_segmented_file[-1]) == 512:
            packets.append(struct.pack('!HH', TftpPacketType.DATA.value, i))

        return packets

    @staticmethod
    def gen_wrq(filename):
        file_name_len = len(filename)
        fmt = f'!H{file_name_len}sc5sc'
        return struct.pack(fmt, TftpPacketType.WRQ.value, bytes(filename, 'ASCII'), bytes(chr(0), 'ASCII'),
                           bytes('octet', 'ASCII'), bytes(chr(0), 'ASCII'))

    @staticmethod
    def gen_rrq(filename):
        file_name_len = len(filename)
        fmt = f'!H{file_name_len}sc5sc'
        return struct.pack(fmt, TftpPacketType.RRQ.value, bytes(filename, 'ASCII'), bytes(chr(0), 'ASCII'),
                           bytes('octet', 'ASCII'), bytes(chr(0), 'ASCII'))

    @staticmethod
    def gen_err_msg(error_code):
        error_message = bytes(tftp_error_messages[error_code], 'ASCII')
        fmt = f'!HH{len(error_message)}sc'
        return struct.pack(fmt, TftpPacketType.ERROR.value, error_code, error_message, bytes(chr(0), 'ASCII'))

    @staticmethod
    def gen_ack(block_no):
        return struct.pack('!HH', TftpPacketType.ACK.value,  block_no)

    @staticmethod
    def get_block_num(packet):
        first_two_bytes = packet[0:2]
        opcode = struct.unpack('!H', first_two_bytes)[0]
        sz = len(packet)

        if opcode == TftpPacketType.DATA.value:
            strlen = sz - 4
            fmt = f'!HH{strlen}s'
            return struct.unpack(fmt, packet)[1]
        elif opcode == TftpPacketType.ACK.value:
            return struct.unpack('!HH', packet)[1]
        else:
            return 0

    @staticmethod
    def get_opcode(packet):
        first_two_bytes = packet[0:2]
        return struct.unpack('!H', first_two_bytes)[0]

class FileHandler:

    def __init__(self, filename):
        self.filename = filename
        self.array = []

    def read_and_segment(self):
        f = open(self.filename, 'rb')
        while True:
            self.array.append(f.read(512))
            if len(self.array[len(self.array) - 1]) < 512:
                break
        return self.array


class TftpPacketType(enum.Enum):
    RRQ = 1
    WRQ = 2
    DATA = 3
    ACK = 4
    ERROR = 5


class TftpProcessor(object):

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.downloaded_file_content = b""
        self.current_operation = None
        self.file_segments = None
        self.buffered_packet = []
        self.end_flag = False
        self.next_block_no = 0
        pass

    def set_upload(self):
        self.current_operation = UPLOAD

    def set_download(self):
        self.current_operation = DOWNLOAD

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        if out_packet is not None:
            self.packet_buffer.append(out_packet)
            self.next_block_no += 1

    def _parse_udp_packet(self, packet_bytes: bytes) -> dict:
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        first_two_bytes = packet_bytes[0:2]
        opcode = struct.unpack('!H', first_two_bytes)[0]

        data = dict()
        data[OPCODE] = opcode

        num_of_bytes = len(packet_bytes)

        if opcode == TftpPacketType.RRQ.value or opcode == TftpPacketType.WRQ.value:
            mode_len = len('octet')
            string_size = num_of_bytes - 2 - 1 - 1 - mode_len
            fmt = f'!H{string_size}sc5sc'
            unpacked = struct.unpack(fmt, packet_bytes)
            data[FILENAME] = unpacked[1]

        elif opcode == TftpPacketType.DATA.value:
            string_size = num_of_bytes - 2 - 2
            fmt = f'!HH{string_size}s'
            unpacked = struct.unpack(fmt, packet_bytes)
            data[BLOCKNO] = unpacked[1]
            data[DATA] = unpacked[2]  # data in last element

        elif opcode == TftpPacketType.ACK.value:
            fmt = '!HH'
            unpacked = struct.unpack(fmt, packet_bytes)
            data[BLOCKNO] = unpacked[1]

        elif opcode == TftpPacketType.ERROR.value:
            string_size = num_of_bytes - 2 - 2 - 1
            fmt = f'!HH{string_size}sc'
            unpacked = struct.unpack(fmt, packet_bytes)
            data[ERRORCODE] = unpacked[1]
            data[ERRMSG] = unpacked[2]

        print('Dictionary of items in parse udp : ', data)

        return data

    def _do_some_logic(self, input_packet: dict):
        """
        Example of a private function that does some logic.
        """
        opcode = input_packet[OPCODE]
        out_packet = None
        if opcode == TftpPacketType.DATA.value:
            self.downloaded_file_content += input_packet[DATA]
            if len(input_packet[DATA]) < 512:
                self.end_flag = True
            out_packet = Packer.gen_ack(input_packet[BLOCKNO])

        elif opcode == TftpPacketType.ACK.value:
            if self.current_operation == UPLOAD:
                if len(self.file_segments) == 0:
                    return None
                byte_arr = self.file_segments.pop(0)
                out_packet = struct.pack(f'!HH{len(byte_arr)}s', TftpPacketType.DATA.value,
                                         input_packet[BLOCKNO] + 1, byte_arr)

        elif opcode == TftpPacketType.ERROR.value:
            print(f'Error!!\nType : {input_packet[ERRMSG].decode("ASCII")}')
            exit(str(input_packet[ERRORCODE]))

        else:
            print(f"Unknown operation code {input_packet[OPCODE]}....\nTerminating....")
            out_packet = Packer.gen_err_msg(4)

        return out_packet

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.

        For example;
        s_socket.send(tftp_processor.get_next_output_packet())

        Leave this function as is.
        """
        self.buffered_packet = self.packet_buffer[0]
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        self.set_download()
        p = Packer(self.file_segments)
        rrq_packet = p.gen_rrq(file_path_on_server)
        self.packet_buffer.extend([rrq_packet])
        pass

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        fh = FileHandler(file_path_on_server)
        self.file_segments = fh.read_and_segment()
        self.set_upload()
        p = Packer(self.file_segments)
        wrq_packet = p.gen_wrq(file_path_on_server)
        self.packet_buffer.extend([wrq_packet])
        pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def send_error_message(client_socket, server_address, packet):
    client_socket.sendto(packet, server_address)


def send_to_server(client_socket, old_server_address, packet, tftp_proccessor: TftpProcessor):
    client_socket.sendto(packet, old_server_address)

    if Packer.get_opcode(packet) == TftpPacketType.ERROR.value:
        exit(TftpPacketType.ERROR.value)

    if tftp_proccessor.end_flag:
        return old_server_address, packet

    count = 0

    while True:
        if count == 3:
            print('Timed Out...\nExiting...')
            exit(-1)

        count += 1
        client_socket.settimeout(2)

        try:
            data, server_address = client_socket.recvfrom(4096)

            if server_address != old_server_address and old_server_address[1] != 69:
                error_packet = Packer.gen_err_msg(5)
                client_socket.sendto(error_packet, server_address)
                continue

            if Packer.get_block_num(data) != Packer.get_block_num(tftp_proccessor.buffered_packet):
                print("Wrong block number : we chose to ignore this as we weren't told how to handle this")

            return server_address, data
        except socket.timeout:
            client_socket.sendto(packet, old_server_address)
        except ConnectionError:
            print('Connection Error!!\nExiting...')
            exit(-1)

    raise Exception('Logical error...')


def upload(file_name, server_address):
    tftp = TftpProcessor()
    tftp.upload_file(file_name)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (server_address, 69)
    packet = tftp.get_next_output_packet()
    server_address, received_packet = send_to_server(client_socket, server_address, packet, tftp)
    tftp.process_udp_packet(received_packet, server_address)

    while tftp.has_pending_packets_to_be_sent():
        packet = tftp.get_next_output_packet()
        server_address_received, received_packet = send_to_server(client_socket, server_address, packet, tftp)
        tftp.process_udp_packet(received_packet, server_address)


def download(file_name, server_address):
    tftp = TftpProcessor()
    tftp.request_file(file_name)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (server_address, 69)

    packet = tftp.get_next_output_packet()
    server_address, received_packet = send_to_server(client_socket, server_address, packet, tftp)
    tftp.process_udp_packet(received_packet, server_address)

    while tftp.has_pending_packets_to_be_sent():
        packet = tftp.get_next_output_packet()
        server_address_received, received_packet = send_to_server(client_socket, server_address, packet, tftp)
        tftp.process_udp_packet(received_packet, server_address)

    f = open(file_name, 'wb')
    f.write(tftp.downloaded_file_content)
    f.close()


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        upload(file_name, address)
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        download(file_name, address)
        pass


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
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
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "push")
    file_name = get_arg(3, "newtest.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()