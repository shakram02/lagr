import sys
import os
import enum
import socket
import struct


class TftpProcessor(object):
    """
    Implements logic for a TFTP server.
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
        pass

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.type = -1
        self.curr_block = 0
        self.f = None
        pass

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
        out_packet = self._do_tftp_logic(in_packet)

        if out_packet != -1:
            # This shouldn't change.
            self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        # using struct module here is painstaking as there
        # is no way to know the size of file name and and type
        opcode = packet_bytes[0:2]
        opcode = int.from_bytes(opcode, "big")

        if opcode == self.TftpPacketType.RRQ.value or opcode == self.TftpPacketType.WRQ.value:
            name_end = packet_bytes[2:].find(0) + 2
            filename = packet_bytes[2:name_end].decode('ASCII')
            mode_end = packet_bytes[name_end + 1:].find(0) + name_end + 1
            mode = packet_bytes[name_end + 1:mode_end].decode('ASCII')
            return opcode, filename, mode
        elif opcode == self.TftpPacketType.ACK.value:
            block_n = int.from_bytes(packet_bytes[2:4], "big")
            return opcode, block_n
        elif opcode == self.TftpPacketType.DATA.value:
            block_n = int.from_bytes(packet_bytes[2:4], "big")
            raw_data = packet_bytes[4:]
            return opcode, block_n, raw_data
        elif opcode == self.TftpPacketType.ERROR.value:
            err_code = int.from_bytes(packet_bytes[2:4], "big")
            msg_end = packet_bytes[4:].find(0) + 4
            err_msg = packet_bytes[4:msg_end].decode('ASCII')
            return opcode, err_code, err_msg
        else:
            return self.get_error_packet(4)

    # noinspection PyTypeChecker
    def _do_tftp_logic(self, input_packet):
        opcode = input_packet[0]

        if opcode == self.TftpPacketType.RRQ.value:  # filename, mode
            self.type = self.TftpPacketType.RRQ
            self.curr_block = 0

            if self.f is not None:
                self.f.close()

            try:
                self.f = open(input_packet[1], "rb")
            except IOError:
                print("File not accessible")
                return self.get_error_packet(1)

            packet = self.get_data_and_pack()
            return packet

        elif opcode == self.TftpPacketType.WRQ.value:  # filename, mode
            self.type = self.TftpPacketType.WRQ
            self.curr_block = 0
            if self.f is not None:
                self.f.close()
            self.f = open(input_packet[1], "wb")
            packet = b'\x00\x04\x00\x00'
            return packet

        elif opcode == self.TftpPacketType.ACK.value:  # block_n
            self.type = self.TftpPacketType.ACK
            if input_packet[1] == self.curr_block - 1:
                packet = self.get_data_and_pack()
                return packet

            elif self.curr_block == 0:
                return -1

            else:
                return self.get_error_packet(5)

        elif opcode == self.TftpPacketType.DATA.value:  # block_n, raw_data
            self.type = self.TftpPacketType.DATA
            if input_packet[1] == self.curr_block + 1:
                self.f.write(input_packet[2])
                if len(input_packet[2]) < 512:
                    self.f.close()
                self.curr_block += 1
                packet = struct.pack("!hh", 4, self.curr_block)
                return packet
            else:
                # error ack
                pass
            pass
        elif opcode == self.TftpPacketType.ERROR.value:  # err_code, err_msg
            self.type = self.TftpPacketType.ERROR
            pass
        else:
            exit(-1)
            pass

    def get_data_and_pack(self):

        counter = 511
        data = b""
        byte = self.f.read(1)
        data += byte
        while byte and counter != 0:
            byte = self.f.read(1)
            data += byte
            counter -= 1

        packet = struct.pack("!hh{}s".format(512 - counter), 3, self.curr_block, data)
        if counter != 0:
            self.curr_block = 0
        else:
            self.curr_block += 1

        return packet

    @staticmethod
    def get_error_packet(err_n):
        if err_n == 0:
            err_msg = b"Not defined, see error message (if any)."
        elif err_n == 1:
            err_msg = b"File not found."
        elif err_n == 2:
            err_msg = b"Access violation."
        elif err_n == 3:
            err_msg = b"Disk full or allocation exceeded."
        elif err_n == 4:
            err_msg = b"Illegal TFTP operation."
        elif err_n == 5:
            err_msg = b"Unknown transfer ID."
        elif err_n == 6:
            err_msg = b"File already exists."
        elif err_n == 7:
            err_msg = b"No such user."
        else:
            err_msg = b"Not defined error."

        packet = struct.pack("!hh{}sb".format(len(err_msg)), 5, err_n, err_msg, 0)
        return packet

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
    # don't forget, the server's port is 69 (might require using sudo on Linux)
    print(f"TFTP server started on on [{address}]...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)
    server_socket.bind(server_address)
    return server_socket


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
    # The IP of the server.
    ip_address = get_arg(1, "127.0.0.1")
    server_socket = setup_sockets(ip_address)
    packet = server_socket.recvfrom(4096)
    data, source = packet
    tftp_processor = TftpProcessor()
    tftp_processor.process_udp_packet(data, source)

    while 1:

        while tftp_processor.has_pending_packets_to_be_sent():
            server_socket.sendto(tftp_processor.get_next_output_packet(), source)

        packet = server_socket.recvfrom(4096)
        data, source = packet
        tftp_processor.process_udp_packet(data, source)


if __name__ == "__main__":
    main()
