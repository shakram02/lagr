import socket
import sys
import os
import enum
import struct

string_mode = b"octet"

terminate_length = 516

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ('127.0.0.1', 69)


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

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        pass

    def process_udp_packet(self, file_name, server_packet):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        #print(f"Received a packet from {packet_source}")
        #in_packet = self._parse_udp_packet(packet_data)
        self.read_file(file_name)

       # print(out_packet)

        var = 1
        data_packet = bytearray()
        while(self.has_pending_packets_to_be_sent()):
            data_packet.append(0)
            data_packet.append(3)
            data_packet += struct.pack("!H" , var)
            data_packet += self.get_next_output_packet()
            var += 1
            print(f"Request {data_packet}")
            request = client_socket.sendto(data_packet, server_packet)
            data_packet.clear()
            server_packet1 = client_socket.recv(512)
            if self.check_error(server_packet1):
                client_socket.close()
                client_socket.__exit__()
        # This shouldn't change.
        # self.packet_buffer.append(out_packet)



    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        pass

    def read_file(self, file_name):
        file = open(file_name ,'rb')
        data = file.read(512)
        while(len(data) != 0):
            self.packet_buffer.append(data)
            data = file.read(512)
        file.close()
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

    def request_file(self, filename,mode):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        RRQ_packet = bytearray()
        RRQ_packet.append(0)
        RRQ_packet.append(1)
        # filename = input(str("please input the file name you wish to download:\n"))
        filename = bytearray(filename.encode('utf-8'))
        RRQ_packet += filename
        RRQ_packet.append(0)
        MODE = bytearray(bytes(mode, 'utf-8'))
        RRQ_packet += MODE
        RRQ_packet.append(0)
        #print(f"Request {RRQ_packet}")
        sent = client_socket.sendto(RRQ_packet, (server_address))
        pass


    def send_ACK(self,data_ack, serverAddr):
        ack = bytearray(data_ack)
        #  print(ack)
        ack[0] = 0
        ack[1] = 4
        #print(ack)
        client_socket.sendto(ack, serverAddr)
        pass


    def check_error(self,data):
        object = TftpProcessor()
        opcode = data[:2]
        if opcode[0] == 0 and opcode[1] == 5:
            return 1
        else:
            return 0

    error_msg = {
        0: "Not defined, see error message (if any).",
        1: "File not found.",
        2: "Access violation.",
        3: "Disk full or allocation exceeded.",
        4: "Illegal TFTP operation.",
        5: "Unknown transfer ID.",
        6: "File already exists.",
        7: "No such user."
    }






    def download(self,filename):
        object = TftpProcessor()
        object.request_file(filename, "octet")
        file = open(filename, "wb")
        while True:
            data, server = client_socket.recvfrom(600)
            #print(data.decode("utf-8"))
            if (object.check_error(data)):
                errorcode = int.from_bytes(data[2:4], byteorder='big')
                print(object.error_msg[errorcode])
                break

            object.send_ACK(data[0:4], server)
            packetToFile = data[4:]
            file.write(packetToFile)

            if len(data) < terminate_length:
                print("download completed!\n")
                break

    pass



    def upload_file(self, filename , mode):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        wrq_packet = bytearray()
        wrq_packet.append(0)
        wrq_packet.append(2)
        filename = bytearray(filename.encode('utf-8'))
        wrq_packet += filename
        wrq_packet.append(0)
        mode = bytearray(bytes(mode, 'utf-8'))
        wrq_packet += mode
        wrq_packet.append(0)
        print(f"Request {wrq_packet}")
        request = client_socket.sendto(wrq_packet, server_address)
        pass


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass








def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    object = TftpProcessor()
    if operation == "push":
        object.upload_file(file_name, "octet")
        print(f"Attempting to upload [{file_name}]...")
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        object.download(file_name)
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
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)

    server_packet = client_socket.recvfrom(512)
    print(server_packet[1])

    obj = TftpProcessor()
    obj.process_udp_packet(file_name, server_packet[1])


if __name__ == "__main__":
    main()