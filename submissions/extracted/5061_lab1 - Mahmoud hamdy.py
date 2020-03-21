#importing libraries and declaring global variables
temp = bytearray()
import sys
import os
import socket
import struct
import enum

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
        WR = 2
        Data = 3
        Ack = 4
        Error = 5

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
        Extract the opcode to know the type of the received packet then extract the whole packet according to its type
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line

        print(f"Received a packet from {packet_source}")

        code = packet_data[1]
        in_packet = self._parse_udp_packet(packet_data, code)
        out_packet = self._do_some_logic(in_packet, code)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes, code):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        if code == 3: #DATA
            global temp
            indicator = packet_bytes[2:4]
            temp = temp + packet_bytes[4:]
            return indicator

        elif code == 4:  # ACKNWOELDGE
            indicator = packet_bytes[1]
            indicator + 1
            return indicator

        elif code == 5:  # ERROR
            error = packet_bytes[2:4]
            msg = packet_bytes[4:]
            return error
        pass

    def _do_some_logic(self, input_packet, code):
        """
        Send Ack when receive Data and Send Data when Receive Ack
        Example of a private function that does some logic.
        """
        if code == 3: # SEND ACK
            packet = bytearray()
            packet.append(0)
            packet.append(4)
            packet += input_packet
            return packet

        pass

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

        requested_file= file_path_on_server
        rrq= bytearray()
        rrq.append(0)
        rrq.append(1)
        name= bytearray(requested_file, 'ASCII')
        rrq= rrq+name
        rrq.append(0)
        mode= bytearray('octet', 'ASCII')
        rrq= rrq+mode
        rrq.append(0)
        print(rrq)
        self.packet_buffer.append(rrq)

        pass

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """

        self.packet_buffer.append()
        pass

instance_processor = TftpProcessor()

def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass

def setup_sockets():
    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    address = ('127.0.0.1', 69)
    return client_socket, address

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
        instance_processor.request_file(file_name)
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
    client_socket, server_address = setup_sockets()
    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    file = open(file_name, "r")
    read = file.read()
    length = int(len(read) / 512)
    input = []
    for i in range(length):
        input[i] = bytearray(read)[i * 512:(i + 1) * 512]
    print(read)

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)
    while instance_processor.has_pending_packets_to_be_sent():
        nextpacket = instance_processor.get_next_output_packet()
        client_socket.sendto(nextpacket, server_address)
        receivepacket = client_socket.recvfrom(516)
        packet_data, server_address = receivepacket
        instance_processor.process_udp_packet(packet_data, server_address)
        if (len(packet_data) < 516):
            break
    ftp = open(file_name, 'w', newline='')
    ftp.write(temp.decode('ASCII'))
    ftp.close()

if __name__ == "__main__":
    main()
