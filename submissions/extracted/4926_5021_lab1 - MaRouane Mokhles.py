# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
from socket import timeout


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
    num_packets = 0
    block_number = 1
    data_buffer = []
    reserve_packet = []
    downloaded_file = bytearray()
    error_messages = {
        0: "Not defined, see error message (if any).",
        1: "File not found.",
        2: "Access violation.",
        3: "Disk full or allocation exceeded.",
        4: "Illegal TFTP operation.",
        5: "Unknown transfer ID.",
        6: "File already exists.",
        7: "No such user."
    }

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
        reply = self._parse_udp_packet(packet_data)
        # Add downloaded data packet to file, if the received packet is DATA
        if reply == "DATA":
            data_packet = packet_data[4:]
            self.downloaded_file += data_packet
            if len(data_packet) < 512:
                return "DONE"
        return reply

    def get_block_number(self, packet_data):
        return packet_data[2:4]

    def decode_dload_file(self):
        file_content = self.downloaded_file.decode('ascii', 'strict')
        filename = input("Please enter output file name (with extension)\n")
        f = open(filename, "w+")
        f.write(file_content)
        f.close()

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        opcode = packet_bytes[:2]

        operation = int.from_bytes(opcode, 'big')
        print("OPcode: ", operation)
        print("Block#: ", int.from_bytes(packet_bytes[2:4], 'big'))
        if operation == 5:
            error_msg = self.error_messages[int.from_bytes(packet_bytes[2:4], 'big')]
            reply = "ERROR"
            print(error_msg)
        elif operation == 3:
            reply = "DATA"
        elif operation == 4:
            reply = "ACK"
        else:
            reply = "UNK"
        return reply

    def _do_some_logic(self):
        """
        Example of a private function that does some logic.
        """
        # Returns a TFTP DATA packet using
        # OPCODE 03 (in 2 bytes)
        # BLOCK NUM (in 2 bytes)
        # DATA      (in MAX(512) bytes)

        ret_packet = bytearray()
        ret_packet.append(0)
        ret_packet.append(3)
        if self.block_number <= 256:
            ret_packet.append(0)
        ret_packet.append(self.block_number)
        self.block_number += 1
        ret_packet += self.data_buffer[0]
        self.reserve_packet = self.data_buffer[0]
        del[self.data_buffer[0]]
        return ret_packet

    def get_reserve_packet(self):
        # In case a packet was not sent, the program calls this method to return it
        # So it could be sent again

        return self.reserve_packet

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a bytearray representing
        the next packet to be sent.

        For example;
        s_socket.send(tftp_processor.get_next_output_packet())

        Leave this function as is.
        """

        if self.num_packets != 0:
            packet = self._do_some_logic()
            self.num_packets -= 1
            return packet

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return self.num_packets != 0

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        # Create a RRQ
        packet = bytearray()
        packet.append(0)
        packet.append(1)
        name_barr = bytearray(file_path_on_server.encode('ascii'))
        packet += name_barr
        packet.append(0)
        mode = bytearray("octet".encode('ascii'))
        packet += mode
        packet.append(0)
        return packet

    def upload_file(self, filename):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        # Convert file to bytearray
        try:
            file = open(filename, "rb")
        except IOError:
            print("Your file doesn't exist")
            exit(12)
        data = file.read()
        contents = bytearray()
        contents.extend(data)
        # Create the data buffer and fill it with 512 B sized blocks of data from the file content
        offset = 0
        while offset < len(contents):
            self.data_buffer.append(contents[offset: offset + 512])
            offset += 513
            self.num_packets += 1

        # Create a WRQ
        packet = bytearray()
        packet.append(0)
        packet.append(2)
        name_barr = bytearray(filename.encode('ascii'))
        packet += name_barr
        packet.append(0)
        mode = bytearray("octet".encode('ascii'))
        packet += mode
        packet.append(0)

        return packet


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
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return udp_sock


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    pass


def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code. 
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
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
    port = 69

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)
    udp_socket = setup_sockets(ip_address)
    tftp_proc = TftpProcessor()
    packet = []
    reply = ''
    if operation == "push":
        packet = tftp_proc.upload_file(file_name)
    elif operation == "pull":
        packet = tftp_proc.request_file(file_name)
    # Send a WRQ or RRQ to the Server IP address on port 69
    udp_socket.sendto(packet, (ip_address, port))
    if operation == "push":
        inc_packet, (host, new_port) = udp_socket.recvfrom(1000)
        reply = tftp_proc.process_udp_packet(inc_packet, ip_address)
    # Acquire an acknowledgement packet, the host address and the upload port
    # Determine if received packet was ACK or ERROR
    if reply == "ACK":
        print("Connection Established")
        while True:
            if operation == "push":
                if tftp_proc.has_pending_packets_to_be_sent() != 0:
                    # Acquire and the next TFTP packet to be sent
                    sen_packet = tftp_proc.get_next_output_packet()
                    print("Packet Size = ", len(sen_packet))
                    udp_socket.sendto(sen_packet, (ip_address, new_port))
                    num_tries = 0
                    while num_tries < 4:
                        try:
                            num_tries += 1
                            inc_packet, server = udp_socket.recvfrom(1000)
                            break
                        except timeout:
                            print("Request timed out!")
                            udp_socket.sendto(tftp_proc.get_reserve_packet(), (ip_address, new_port))
                    reply = tftp_proc.process_udp_packet(inc_packet, ip_address)
                    if reply != "ACK":
                        break
                else:
                    break
    if operation == "pull":
        while True:
            num_tries = 0
            rec_packet = []
            server = ''
            ass_port = ''
            # Try receiving a packet from the server
            # If after 4 timeouts it doesn't work, terminate the program
            while num_tries < 4:
                try:
                    num_tries += 1
                    rec_packet, (server, ass_port) = udp_socket.recvfrom(516)
                    print("Received Packet size: ", len(rec_packet))
                    break
                except timeout:
                    print("Request timed out ... Trying again!")
            if num_tries != 4:
                reply = tftp_proc.process_udp_packet(rec_packet, server)
                if reply == "DONE":
                    tftp_proc.decode_dload_file()
                    print("Download Complete ...")
                    exit(0)
                elif reply == "ERROR":
                    break
                elif reply == "DATA":
                    pass
                block_num = tftp_proc.get_block_number(rec_packet)
                ack_packet = bytearray()
                ack_packet.append(0)
                ack_packet.append(4)
                ack_packet += block_num
                udp_socket.sendto(ack_packet, (ip_address, ass_port))
            else:
                print("Failed to receive packet due to timeout. Please try again later!")
                exit(12)


if __name__ == "__main__":
    main()