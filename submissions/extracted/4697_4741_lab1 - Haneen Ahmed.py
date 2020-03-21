import sys
import os
import enum
import socket as s
import struct
from queue import Queue

ErrorMessages = {
    0: 'Not defined!',
    1: 'File not found!',
    2: 'Access violation',
    3: 'Disk full or allocation exceeded',
    4: 'Illegal TFTP operation',
    5: 'Unknown transfer ID',
    6: 'File already exists',
    7: 'No such user',
    8: 'Invalid options specified',
}


class TftpProcessor(object):
    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self, Mode, PacketSize, Port, file_name):

        self.mode = Mode
        self.packet_size = PacketSize
        self.packet_buffer = []
        self.port = Port
        self.types = TftpProcessor.TftpPacketType
        self.FileName = file_name
        self.queue = Queue()
        pass

    def process_udp_packet(self, packet_data, packet_source):

        if packet_source[1] != self.port:
            print(f"Received data from an unknown server {packet_source[1]}")
            sys.exit()
        else:
            print(f"Received a packet from {packet_source}")
            print(f"Received Data: {packet_data}")

            in_packet = self._parse_udp_packet(packet_data)
            out_packet = self._do_some_logic(in_packet)
            print(f"Out packet: {out_packet}")

            if out_packet != -1:
                self.packet_buffer.append(out_packet)  # This shouldn't change.
                print("Buffer appended")
            else:
                exit()

    def _parse_udp_packet(self, packet_bytes):

        Opcode = packet_bytes[1]
        if Opcode == self.types.DATA.value:
            UnpackedPacket = struct.unpack('!HH{}s'.format(len(packet_bytes) - 4), packet_bytes)
        elif Opcode == self.types.ACK.value:
            UnpackedPacket = struct.unpack('!HH', packet_bytes)
        elif Opcode == self.types.ERROR.value:
            UnpackedPacket = [Opcode, packet_bytes[3]]
        else:
            print(f"ERROR! Unrecognized Opcode {Opcode}")
        return UnpackedPacket

    def _do_some_logic(self, input_packet):
        if input_packet[0] == self.types.DATA.value:
            print(f"Data Chunk: {input_packet[2]}")
            self.queue.put(input_packet[2])
            BlockNumber = input_packet[1]
            self.WriteToFile()
            Reply = struct.pack("!HH", self.types.ACK.value, BlockNumber)

        elif input_packet[0] == self.types.ACK.value:
            BlockNumber = input_packet[1]
            message_to_be_sent = self.queue.get()
            # Send Data opcode + block number received +1 + chunk of data
            ReplyFormat = "!HH{}s".format(len(message_to_be_sent))
            Reply = struct.pack(ReplyFormat, self.types.DATA.value, BlockNumber + 1,
                                bytearray(message_to_be_sent))

        elif input_packet[0] == self.types.ERROR.value:
            ErrorCode = input_packet[1]
            print(f"ERROR! {ErrorMessages[ErrorCode]}")
            Reply = -1  # Terminate

        return Reply

    def ReadFromFile(self):
        f = open(self.FileName, "rb")
        message = f.read()
        print(f"Message: {message}")
        f.close()
        for part in self.chunker(message, self.packet_size):
            self.queue.put(part)
        if self.queue.empty():
            print("ERROR! File is empty")
            exit()

    def WriteToFile(self):
        f = open("download.txt", "ba")
        f.write(self.queue.get())
        f.close()

    def chunker(self, seq, size):
        return (seq[pos:pos + size] for pos in range(0, len(seq), size))

    def get_next_output_packet(self):  # Leave this function as it is.
        # Pop first element in the packet buffer
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):  # Leave this function as is.
        # Returns 1 if buffer is not empty
        return len(self.packet_buffer) != 0

    def request_file(self, file_path_on_server):
        # RRQ
        Filename = bytearray(file_path_on_server.encode('utf-8'))
        # x --> padding with 0 / H --> unsigned short / s --> string
        Reqformat = "!H{}sx{}s".format(len(file_path_on_server), len(self.mode))
        Request = struct.pack(Reqformat, TftpProcessor.TftpPacketType.RRQ.value, Filename, self.mode)
        print(f"Request: {Request}")

        return Request

    def upload_file(self, file_path_on_server):
        # WRQ
        Filename = bytearray(file_path_on_server.encode('utf-8'))
        # x --> padding with 0 / H --> unsigned short / s --> string
        Reqformat = "!H{}sx{}sx".format(len(file_path_on_server), len(self.mode))
        Request = struct.pack(Reqformat, TftpProcessor.TftpPacketType.WRQ.value, Filename, self.mode)
        print(f"Request: {Request}")
        self.ReadFromFile()

        return Request


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    try:
        ClientSocket = s.socket(family=s.AF_INET, type=s.SOCK_DGRAM)
        ServerAddress = (address, 69)
        print("Client socket initialized")
    except s.error:
        print("Failed to create socket")
        sys.exit()
    return ClientSocket, ServerAddress


def parse_user_input(address, operation, file_name=None):
    if operation == "push":
        print(f"Attempting to upload [{file_name}] to IP address {address}...")
        PushPullFlag = 0

    elif operation == "pull":
        print(f"Attempting to download [{file_name}] from IP address {address}...")
        PushPullFlag = 1
    else:
        print("Error: unrecognized request...")
        exit()
    return PushPullFlag


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

    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test2.txt")

    if ip_address != "127.0.0.1":
       print("Error: server doesn't exist...")
       exit()

    PushPullFlag = parse_user_input(ip_address, operation, file_name)
    ClientSocket, ServerAddress = setup_sockets(ip_address)

    TFTP = TftpProcessor(b'octet', 512, 69, file_name)

    if PushPullFlag == 0:
        Request = TFTP.upload_file(file_name)
    else:
        Request = TFTP.request_file(file_name)

    ClientSocket.sendto(Request, ServerAddress)

    while True:
        Data, ClientAddress = ClientSocket.recvfrom(TFTP.packet_size + 4)
        TFTP.process_udp_packet(Data, ServerAddress)

        if TFTP.has_pending_packets_to_be_sent() == 1:
            MessageSent = ClientSocket.sendto(TFTP.get_next_output_packet(), ClientAddress)
            print(f"Message sent: {MessageSent}")


if __name__ == "__main__":
    main()
