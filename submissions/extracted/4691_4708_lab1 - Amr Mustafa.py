# Don't forget to change this file's name before submission.
import sys
import os
import enum
import time
from socket import *
from struct import *

TFTP_PORT = 69
BUFFER_SIZE = 650


class TftpProcessor(object):
    """
    Implements logic for a TFTP client.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.
    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.
    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.
    This class is also responsible for reading/writing files to the
    hard disk.
    Failing to comply with those requirements will invalidate
    your submission.
    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.out_buffer = ""
        self.in_buffer = []
        self.block_no = 1
        self.last_block_no = 0
        self.terminate = False
        self.file_name = ""

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        print(f"[INFO] Received a packet from {packet_source}")

        packet_fields = self._parse_udp_packet(packet_data)
        if (packet_fields["TYPE"] == "DATA" and not self.is_duplicate_packet(packet_fields)) or (packet_fields["TYPE"] != "DATA"):
            out_packet = self.respond_to_packet(packet_fields)
            if out_packet: self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        type_field = packet_bytes[1] + packet_bytes[0] * 256

        if (type_field == TftpProcessor.TftpPacketType.RRQ.value) or (
                type_field == TftpProcessor.TftpPacketType.WRQ.value):

            packet_type = "RRQ" if (type_field == TftpProcessor.TftpPacketType.RRQ.value) else "WRQ"

            filename_bytes = []
            for byte in packet_bytes[2:]:
                filename_bytes.append(byte)
                if byte == 0: break
            filename = unpack(str(len(filename_bytes)) + "s", bytes(filename_bytes))

            mode_bytes = []
            for byte in packet_bytes[(2 + len(filename_bytes)):]:
                mode_bytes.append(byte)
                if byte == 0: break
            mode = unpack(str(len(mode_bytes)) + "s", bytes(mode_bytes))

            return {"TYPE": packet_type, "FILE_NAME": filename, "MODE": mode}

        elif type_field == TftpProcessor.TftpPacketType.DATA.value:

            packet_type = "DATA"
            block_number = packet_bytes[3] + packet_bytes[2] * 256
            data = packet_bytes[4:]

            return {"TYPE": packet_type, "BLOCK_NO": block_number, "DATA": data}

        elif type_field == TftpProcessor.TftpPacketType.ACK.value:

            packet_type = "ACK"
            block_number = packet_bytes[2] + packet_bytes[3] * 256

            return {"TYPE": packet_type, "BLOCK_NO": block_number}

        elif type_field == TftpProcessor.TftpPacketType.ERROR.value:

            packet_type = "ERROR"
            error_code = packet_bytes[2] + packet_bytes[3] * 256

            error_msg_bytes = []
            for byte in packet_bytes[4:]:
                error_msg_bytes.append(byte)
                if byte == 0: break
            error_msg = unpack(str(len(error_msg_bytes)) + "s", bytes(error_msg_bytes))

            return {"TYPE": packet_type, "ERROR_CODE": error_code, "ERROR_MSG": error_msg}

    def respond_to_packet(self, packet_fields):

        packet_type = packet_fields["TYPE"]

        # DATA packets are the response of a previously sent RRQ or ACK packet and are responded to by
        # ACK or ERROR packets.
        if packet_type == "DATA":

            self.last_block_no = packet_fields["BLOCK_NO"]

            # A DATA packet is acknowledged with a ACK package.
            out_packet = pack("!HH", self.TftpPacketType.ACK.value, packet_fields["BLOCK_NO"])

            # Store the data into the incoming data buffer.
            self.in_buffer.append(packet_fields["DATA"])

            # If the length of the incoming data block is less than 512 bytes, then this is the last
            # data block and signals end of the transfer.
            if len(packet_fields["DATA"]) < 512:
                print("[INFO] Last data packet received")
                self._write_file(self.file_name, self.in_buffer)
                self.terminate = True

            return out_packet

        # ACK packages are the response of a previously sent WRQ packet and are responded to by
        # DATA or ERROR packets.
        elif packet_type == "ACK":

            # Fetch the next data block from output file buffer.
            if len(self.out_buffer) > 512:
                data_block = self.out_buffer[(self.block_no - 1) * 512: self.block_no * 512]
                self.out_buffer = self.out_buffer[self.block_no * 512:]
            else:
                print("[INFO] Last data packet sent")
                self.terminate = True
                data_block = self.out_buffer[0:]

            # A ACK packet is acknowledged with a DATA packet.
            out_packet = pack("!HH{}s".format(len(data_block)), self.TftpPacketType.DATA.value, self.block_no, data_block)
            self.block_no = self.block_no + 1

            return out_packet

        # How do we respond to ERROR packets?
        elif packet_type == "ERROR":
            print("[ERROR] {}".format(packet_fields["ERROR_MSG"][0].decode("utf-8")))
            self.terminate = True

    def is_duplicate_packet(self, packet_fields):
        return self.last_block_no == packet_fields["BLOCK_NO"]

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.
        For example;
        s_socket.send(tftp_processor.get_next_output_packet())
        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.
        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def _write_file(self, file_name, input_buffer):
        file = open(file_name, 'w')
        for input in input_buffer:
            file.write(input.decode("ascii"))
        file.close()

    def request_file(self, file_path_on_server):

        self.file_name = file_path_on_server
        return pack("!H" + str(len(file_path_on_server)) + "sB" + str(len("octet")) + "sB",
                    self.TftpPacketType.RRQ.value, file_path_on_server.encode("ascii"), 0, "octet".encode("ascii"), 0)

    def upload_file(self, file_path_on_server):

        file = open(file_path_on_server, 'r')
        buffer = file.readlines()
        for line in buffer:
            self.out_buffer += line
        self.out_buffer = self.out_buffer.encode("ascii")

        return pack("!H" + str(len(file_path_on_server)) + "sB" + str(len("octet")) + "sB",
                    self.TftpPacketType.WRQ.value, file_path_on_server.encode("ascii"), 0, "octet".encode("ascii"), 0)


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """
    sock = socket(AF_INET, SOCK_DGRAM)
    server_address = (address, TFTP_PORT)
    return sock, server_address


def send_packet(socket, address, packet):
    print("[INFO] Sending a packet to {}".format(address))
    socket.sendto(packet, address)


def receive_packet(socket):
    packet = socket.recvfrom(BUFFER_SIZE)
    return packet


def initiate_operation(address, operation, file_name):

    tftp_processor = TftpProcessor()
    sock, server_address = setup_sockets(address)

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        packet = tftp_processor.upload_file(file_name)

    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        packet = tftp_processor.request_file(file_name)

    send_packet(sock, server_address, packet)

    return tftp_processor, sock, server_address


def initiate_communication_loop(tftp_processor, sock, address):
    while not tftp_processor.terminate:
        packet, sender_address = receive_packet(sock)
        tftp_processor.process_udp_packet(packet, sender_address)
        while tftp_processor.has_pending_packets_to_be_sent():
            packet = tftp_processor.get_next_output_packet()
            send_packet(sock, sender_address, packet)
    sock.close()


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
            exit(-1)    # Program execution failed.


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
    file_name = get_arg(3, "test.txt")

    tftp_processor, sock, address = initiate_operation(ip_address, operation, file_name)
    initiate_communication_loop(tftp_processor, sock, address)
    print("[INFO] End of transfer")


if __name__ == "__main__":
    main()
