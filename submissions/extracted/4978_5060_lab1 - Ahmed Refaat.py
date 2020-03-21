import sys
import os
import enum
import socket
import struct
import math
data = bytearray()
input=[]

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
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        lama bygele el packet b call el func deh w bdlha el data w server
        parse extract opcode
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line

        print(f"Received a packet from {packet_source}")

        opcode = packet_data[1]
        in_packet = self._parse_udp_packet(packet_data,opcode)
        out_packet = self._do_some_logic(in_packet,opcode)

        # This shouldn't change.
        processor.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes,opcode):
        """

        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        if opcode==3:
            global data
            block_number = packet_bytes[2:4]
            data = data + packet_bytes[4:]
            return block_number
        elif opcode == 5:  # error packet
            error_code = packet_bytes[2:4]
            error_msg = packet_bytes[4:]
            print('Error:', error_msg.decode('ASCII'))
            return  error_code
        elif opcode == 4:  # acknowledgmenet packet
            block_number = packet_bytes[2:]
            return block_number
        pass

    def _do_some_logic(self, input_packet,opcode):
        """
        ana gale data bb3at ack
        lao gale ack bb3at data
        Example of a private function that does some logic.
        """
        if opcode==3:
            ack_packet = bytearray()
            ack_packet.append(0)
            ack_packet.append(4)
            ack_packet += (input_packet)
            #processor.packet_buffer.append(ack_packet)
            return ack_packet
        elif opcode==4:
            #global input
            data_packet = bytearray()
            data_packet.append(0)
            data_packet.append(3)
            print("PACKET",input_packet)
            print(len(input))
            data_packet.append(0)
            data_packet.append(int.from_bytes(input_packet, "big") + 1)
            data_packet = data_packet + input[int.from_bytes(input_packet,"big")]

            return data_packet
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

        file=file_path_on_server
        rrq_packet=bytearray()
        rrq_packet.append(0)
        rrq_packet.append(1)
        
        fileName = bytearray(file, 'ASCII')
        rrq_packet = rrq_packet + fileName
        rrq_packet.append(0)
        
        mode = bytearray('octet', 'ASCII')
        rrq_packet = rrq_packet + mode
        rrq_packet.append(0)
        print(rrq_packet)

        """
        read = '01'.encode()
        zero = 0
        octet = 'octet'.encode()
        file_name = file_path_on_server.encode()
        rrq_packet=struct.pack('s8sb5sb',read,file_name,zero,octet,zero)
        print(rrq_packet)
        """
        self.packet_buffer.append(rrq_packet)

        pass

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        file = file_path_on_server
        wrq_packet = bytearray()
        wrq_packet.append(0)
        wrq_packet.append(2)

        fileName = bytearray(file, 'ASCII')
        wrq_packet = wrq_packet + fileName
        wrq_packet.append(0)

        mode = bytearray('octet', 'ASCII')
        wrq_packet = wrq_packet + mode
        wrq_packet.append(0)
        print(wrq_packet)
        f = open(file_path_on_server, "r")
        string = f.read().encode()
        number = math.ceil(len(string) / 512)
        for i in range(0,number):
            if len(string[i*512:])<512:
                input.append(string[(number-1) * 512:])
            else:
                input.append(string[i * 512:(i + 1) * 512])


        print("LENGTH: ",len(input))
        """
        read = '01'.encode()
        zero = 0
        octet = 'octet'.encode()
        file_name = file_path_on_server.encode()
        rrq_packet=struct.pack('s8sb5sb',read,file_name,zero,octet,zero)
        print(rrq_packet)
        """
        self.packet_buffer.append(wrq_packet)
        pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('localhost', 69)
    return sock,server_address


def do_socket_logic(message, server_address, sock):
    print('sending {!r}'.format(message))
    sent = sock.sendto(message, server_address)

    # Receive response
    print('waiting to receive')
    data, server = sock.recvfrom(4096)
    print('received {!r}'.format(data))

    """
    bb3at 2w bst2bl mnha
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
        processor.upload_file(file_name)
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")

        processor.request_file(file_name)
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

processor = TftpProcessor()

def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    sock,server_address=setup_sockets()





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
    parse_user_input(ip_address, operation, file_name)
    while processor.has_pending_packets_to_be_sent():
        packet = processor.get_next_output_packet()
        sock.sendto(packet, server_address)
        packet = sock.recvfrom(516)
        packet_data, server_address = packet
        processor.process_udp_packet(packet_data,server_address)
        if(len(packet_data)<516 and operation=="pull"):
            break


    fp = open(file_name, 'w', newline='')
    fp.write(data.decode('ASCII'))
    fp.close()

if __name__ == "__main__":
    main()
