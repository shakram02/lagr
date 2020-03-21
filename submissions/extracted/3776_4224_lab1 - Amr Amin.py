# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct

BUFFER_SIZE = 512


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
        NETASCII_MODE = 'netascii'
        OCTET_MODE = 'octet'

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.block_sent_recieved = 0
        self.port = 45002
        self.upload_chunks = []
        self.retransmission_packet = None
        self.filename = ''
        self.error = None

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
        self.port = packet_source[1]
        if out_packet:
            # This shouldn't change.
            self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        opcode = struct.unpack('!H ', packet_bytes[0:2])[0]
        if opcode == 4:
            block_number = struct.unpack('! H H', packet_bytes)[1]
            # if ack
            if block_number == self.block_sent_recieved:
                # return next data packet data
                self.block_sent_recieved = self.block_sent_recieved + 1
                return self._make_data_packet()
            else:
                # send last packet again
                return self.retransmission_packet
        elif opcode == 3:
            # if data packet

            # get data from packet
            # (opcode, block_number, data) = struct.unpack(
            #     '! H H {}s'.format(BUFFER_SIZE), packet_bytes)
            (data) = struct.unpack('{}s'.format(BUFFER_SIZE), packet_bytes)
            if block_number == 1:
                open(self.filename, 'rb')
            if block_number == self.block_sent_recieved:
                self._write_data_block(data)
                # inc block number recieved
                self.block_sent_recieved = self.block_sent_recieved + 1
                # mack ack packet
                self._make_ack_packet(self.block_sent_recieved)
            else:
                # return ack with prev packet recieved number
                return self.retransmission_packet
        elif opcode == 5:
            print('error ')
            error_code = struct.unpack('! H H', packet_bytes)[1]
            error_msg = struct.unpack('! H H {}s B'.format(
                len(packet_bytes)-5), packet_bytes)[2]
            self.error = (error_code, error_msg)

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        if input_packet is not None:
            return input_packet
        return False

    def _make_rrq_wrq_packet(self, opcode, filename='test.txt', mode='netascii'):
        # makes a packet and adds it to buffer
        values = (opcode, filename.encode('ASCII'), 0, mode.encode('ASCII'), 0)
        packet_format = '! H {}s B {}s B'.format(len(filename), len(mode))
        s = struct.Struct(packet_format)
        self.packet_buffer.append(s.pack(*values))

    def _make_data_packet(self):
        # get first chunk in queue
        if len(self.upload_chunks) > 0:
            data = self.upload_chunks.pop(0)
            values = (self.TftpPacketType.DATA.value,
                      self.block_sent_recieved, data)
            packet_format = '! H H {}s'.format(len(data))
            s = struct.Struct(packet_format)
            # self.packet_buffer.append(s.pack(*values))
            packet = s.pack(*values)
            self.retransmission_packet = packet
            return packet
        return None

    def _make_ack_packet(self, block_number):
        values = (4, block_number)
        packet_format = '! H H'
        s = struct.Struct(packet_format)
        packet = s.pack(*values)
        self.retransmission_packet = packet
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

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        # make RRQ packet
        if self.block_sent_recieved == 0:
            self.filename = file_path_on_server
            self._make_rrq_wrq_packet(
                self.TftpPacketType.RRQ.value, file_path_on_server)
            self._read_chunks()

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """

        # make WRQ packet
        if self.block_sent_recieved == 0:
            self.filename = file_path_on_server
            self._make_rrq_wrq_packet(
                self.TftpPacketType.WRQ.value, file_path_on_server)
            self._read_chunks()

    def _read_chunks(self):
        # read text file in chunks of 512 bytes
        with open(self.filename, 'rb') as f:
            while True:
                read_data = f.read(BUFFER_SIZE).split(b'\x00').pop(0)
                if not read_data:
                    break
                if len(read_data) < 512:
                    read_data = read_data+b'\x00'
                self.upload_chunks.append(read_data)
            f.close()
        # return read_data

    def _write_data_block(self, data):
        with open(self.filename, 'ab') as f:
            f.write(data)
            f.close()
        return True


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    pass


def send_packet_to_server(udp_client_socket, tftp, ip):
    packet = tftp.get_next_output_packet()
    if packet:
        # struct.unpack()
        udp_client_socket.sendto(packet, (ip, tftp.port))
        print('*'*50)
        print("[CLIENT] {} sent".format(packet))
        print('*'*50)


def parse_user_input(address, operation, tftp, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.

    if operation == "push":
        # send WRQ packet to server
        print(f"Attempting to upload [{file_name}]...")
        tftp.upload_file(file_name)
    elif operation == "pull":
        # RRQ packet must be sent to server
        print(f"[CLIENT] Attempting to download [{file_name}]...")
        tftp.request_file(file_name)
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
            exit(-1)    # Program execution failed.


def main():
    """
    Write your code above this function.
    if you need the command line arguments
    """
    tftp = TftpProcessor()
    udp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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

    # Modify this as needed.
    parse_user_input(ip_address, operation, tftp, file_name)
    while tftp.has_pending_packets_to_be_sent():
        if not tftp.error:
            send_packet_to_server(udp_client_socket, tftp, ip_address)
            packet_data, add = udp_client_socket.recvfrom(BUFFER_SIZE)
            if packet_data:
                tftp.process_udp_packet(packet_data, add)
        else:
            print('error occured: ', tftp.error)
            break


if __name__ == "__main__":
    main()
