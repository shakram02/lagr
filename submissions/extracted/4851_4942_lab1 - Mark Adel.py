# Don't forget to change this file's name before submission.
import sys
import os
import enum
import struct
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_address = ()


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

    # done
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

    # done
    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.is_last = 0
        self.op_code = 0
        self.block_no = 0
        self.packet_data = []
        self.error_code = 0
        self.error_message = ""
        self.packet_buffer = []
        self.file_name = ""
        return

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._update_packet(in_packet)

        # This shouldn't change.
        if self.is_last and self.op_code == self.TftpPacketType.ACK.value:
            return
         # -------------------------------change here-------------------------------------------
        if processor.is_last and processor.op_code == processor.TftpPacketType.DATA.value:
            return
        # -------------------------------------------------------------------------------------
        self.packet_buffer.append(out_packet)

    # done
    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        self.op_code = struct.unpack('!H', packet_bytes[:2])[0]

        # if opcode is data
        if self.op_code == self.TftpPacketType.DATA.value:
            self.block_no = struct.unpack('!H', packet_bytes[2:4])[0]
            self.packet_data = packet_bytes[4:]
            self.write_file_in_byte(self.file_name, self.packet_data)

        # if opcode is ack
        elif self.op_code == self.TftpPacketType.ACK.value:
            self.block_no = struct.unpack('!H', packet_bytes[2:4])[0]

        # if opcode is error
        elif self.op_code == self.TftpPacketType.ERROR.value:
            self.error_code = struct.unpack('!H', packet_bytes[2:4])[0]
            self.error_message = packet_bytes[4:]
            self.error_message = self.error_message.decode('ascii')

        return packet_bytes

    def _update_packet(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        if self.op_code == self.TftpPacketType.DATA.value:
            # -------------------------------change here-------------------------------------------
            if len(self.packet_data) < 512:
                self.is_last = 1
            # -------------------------------------------------------------------------------------
            return struct.pack('!HH', self.TftpPacketType.ACK.value, self.block_no)

        elif self.op_code == self.TftpPacketType.ACK.value:
            self.block_no += 1
            file_data = self.read_file_in_byte(self.file_name)[(
                self.block_no - 1) * 512: self.block_no * 512]
            if len(file_data) == 0:
                self.is_last = 1
            return struct.pack('!HH' + str(len(file_data)) + 's', self.TftpPacketType.DATA.value, self.block_no, file_data)

        elif self.op_code == self.TftpPacketType.ERROR.value:
            # TODO: error code
            # return struct.pack('!HH', self.TftpPacketType.DATA.value, self.block_no, )
            pass

        return input_packet

    # leave as is
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

    # leave as is
    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.
        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    def read_file_in_byte(self, file_name):
        file = open(file_name, "rb")
        content = file.read()
        return content

    def write_file_in_byte(self, file_name, file_data):
        file = open(file_name, "ab+")
        file.write(file_data)
        file.close()

    @staticmethod
    def _request_packer(request_type, file_path):
        file_path = file_path.encode('ascii')
        return struct.pack('!H' + str(len(file_path) + 1) + 's6s', request_type, file_path, b"Octet")

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        self.file_name = file_path_on_server
        file = open(self.file_name, "wb")
        file.close()
        self.packet_buffer.append(self._request_packer(
            self.TftpPacketType.RRQ.value, file_path_on_server))
        pass

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        self.file_name = file_path_on_server
        self.packet_buffer.append(self._request_packer(
            self.TftpPacketType.WRQ.value, file_path_on_server))
        pass


processor = TftpProcessor()


# leave as is
def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def do_socket_logic(size):
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    while processor.has_pending_packets_to_be_sent():
        global client_address
        my_packet = processor.get_next_output_packet()
        sock.sendto(my_packet, client_address)
        data, client_address = sock.recvfrom(size)
        processor.process_udp_packet(data, client_address)
    pass


# done
def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    global client_address

    client_address = (address, 69)

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        processor.upload_file(file_name)
        do_socket_logic(4)
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        processor.request_file(file_name)
        do_socket_logic(516)
        pass


# no change just used
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
    ip_address = get_arg(1)
    operation = get_arg(2)
    file_name = get_arg(3)

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)

    """ana ba test hena"""
    # packet = struct.pack('!HH4s', 3, 10, b"Mark")
    # processor = TftpProcessor()
    # processor._parse_udp_packet(packet)
    # print(processor.op_code)
    # print(processor.block_no)
    # print(processor.packet_data)


if __name__ == "__main__":
    main()
