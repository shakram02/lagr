# Don't forget to change this file's name before submission.
import struct
import sys
import os
import enum
from socket import socket
import socket
from typing import Any, Tuple


class TftpProcessor(object):

    is_done = False #For terminating ,after sending the last packet
    block_number = 0 #the expected block number from the server
    file = ""
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
        #WE add all the values of Tftp Type operations
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
        # We append here the file that will be loaded in the file in upload buffer
        self.upload_buffer = []
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

        #In this Function we recieved from parse The packet bytes and the type of operation
        #And from do some logic we recieved the output packet to be sent but at the begin we append in the buufer

        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)



        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        #When we recieved the packet from the server we need to know the type of the operation
        #At first we unpack the first two bytes to get the opcode
       type=struct.unpack('!b',packet_bytes[1:2])[0]
       return type, packet_bytes

    def _ack_format(self, block_num):
        #Before sending the acknowledge to the server we have to formulate the packet
        #Format_ack is the formula to be used for the packing

        format_ack = "!bbh"
        packet = struct.pack(format_ack,0, self.TftpPacketType.ACK.value, block_num)

        return packet

    def _error_format(self):
     #If we recieved a Malformed packet from the server we have to send an error packet to it
     #So we formulate the packet to be sent
        msg = "Malformed Packet"
        format_error = "!HH{}sB".format(len(msg))
        packet = struct.pack(format_error, self.TftpPacketType.ERROR.value, 0, msg.encode(), 0) #error_packet
        return packet

    def _data_handle(self, data, block_num):
        #When we Recieve a data from server we need to check first if its the last or not
        #So we have to check for the length of it if its less than 512 so we set the boolean true and send an acknowledge packet
        #If its not the the last we send an acknolwedge packet
        len_data=len(data)

        if len_data <512:
           self.is_done=True
           self.file.close()

        return self._ack_format(block_num)

    def _ack_handle(self, block_num):
        if block_num <= len(self.upload_buffer):
            data = self.upload_buffer[block_num-1]
            format_data = "!HH{}s".format(len(data))
            packet = struct.pack(format_data, self.TftpPacketType.DATA.value, block_num, data)
        else:
            self.is_done = True
            packet = None
        return packet

    def _do_some_logic(self, in_packet):
     # In this function we check for the opcode :
     # 1- if its data we have to send an ack or an error packet
     #if there is no error we send an ack ,
     #if the length of the packet is less than 4 or the block number expected not equal the block number we send an error packet
        type, packet_bytes = in_packet

        if type == 3:  # data
            if len(packet_bytes) < 4:
                output_packet = self._error_format()
            else:
                block_num = struct.unpack('!H', packet_bytes[2:4])[0]
                data = packet_bytes[4:]
                if self.block_number != block_num or len(data) > 512: #retransmit once again
                    output_packet = self._error_format()
                else:
                    self.block_number+=1
                    self.file.write(data)
                    output_packet = self._data_handle(data, block_num)
         # If its an ack from server than we unpack first the block number to check if its equal the block number or we have to send an error packet
        # if it doesnt contain an error we call ack handle
        elif type == 4:  # ack
            block_num = struct.unpack('!H', packet_bytes[2:4])[0]
            if self.block_number == block_num:
                self.block_number += 1
                output_packet = self._ack_handle(block_num + 1)
            else:
                output_packet = self._error_format()
         # If packet contain an error we unpack the error code and the error mssg
        #to print the error msg if we recieved an error
        elif type == 5:  # error
            error_code = struct.unpack('!H', packet_bytes[2:4])[0]
            msg_bytes = packet_bytes[4:len(packet_bytes) - 1]
            error_message = struct.unpack('!{}s'.format(len(msg_bytes)), msg_bytes)[0]
            # print error as string
            print(error_message)
            sys.exit(error_code)
        else:
            #If its nothing from the above we send and error mssg that its undefined tftp operation
                output_packet=self._error_format()
        return output_packet

    def get_next_output_packet(self):
        #We simply pop from the buffer the acknolwedge to be send
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.

        For example; el satr da mawgoud fel main
        s_socket.send(tftp_processor.get_next_output_packet()) send ta5od packet w teb3atha

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
        #If the client want to get an text from the server at first we open the file to store in it
        #we formulate a read packet to be sent
        self.file = open("download.txt", "wb")
        mode = "octet"
        format_str = ">H{}sB{}sB".format(len(file_path_on_server), len(mode))
        request_packet = struct.pack(format_str, self.TftpPacketType.RRQ.value, file_path_on_server.encode(), 0, mode.encode(), 0)

        return request_packet



    def upload_file(self, file_path_on_server):
        #If the client want to write data to the server
        #we formulate a write packet to be sent at first

        mode="octet"
        packet = self.TftpPacketType
        format_str = "!H{}sB{}sB".format(len(file_path_on_server), len(mode))
        request_packet = struct.pack(format_str, self.TftpPacketType.WRQ.value, file_path_on_server.encode(), 0, mode.encode(), 0)

        return request_packet

    def _handle_file(self, file_name):
        #At first we read the data in a string
        #then we read first 512 bytes to make a data packet then we update the counter by 512 to read the next 512 and so on
        count = 0
        i = 1
        arr_string = []
        file = open(file_name, "rb")
        out_file = file.read()
        while count < len(out_file):
            arr_string.append(out_file[count:count + 512])
            count += 512
            i += 1

        return arr_string

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

    pass


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    pass

def _push( address, operation, file_name):
    #if the client want to write to the server
    #At first we open a connection with the the server address
    #and we send a write packet to server
    #we parse what we get to know the ack or error we recieved
    #we send the dataa and wait for the response and so on
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(1)
    server_address = ("127.0.0.1", 69)
    processor = TftpProcessor()

    print(f"Attempting to upload [{file_name}]...")
    processor.upload_buffer = processor._handle_file(file_name)
    processor.block_number = 0

    packet = processor.upload_file(file_name)
    client_socket.sendto(packet, server_address)
    server_response = client_socket.recvfrom(2048)
    data, address = server_response
    processor.process_udp_packet(data, address)
    while not processor.is_done:
        if processor.has_pending_packets_to_be_sent() == 1:
            out_packet = processor.get_next_output_packet()
            client_socket.sendto(out_packet, address)
            try:
                server_response = client_socket.recvfrom(2048)
                data, address = server_response
                processor.process_udp_packet(data, address)
            except:
                client_socket.sendto(out_packet, address)
                try:
                    server_response = client_socket.recvfrom(2048)
                    data, address = server_response
                    processor.process_udp_packet(data, address)
                except:
                    print("Retry later !")
                    processor.is_done = True

    pass

def _pull(address,operation,file_name):
    #If the client want to get a file from the server
    #at first we send a read request
    #waiting for ther server response of data
    #and sending an acknowledgment to continue and so on
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(1)
    server_address = ("127.0.0.1", 69)
    processor = TftpProcessor()

    print(f"Attempting to download [{file_name}]...")
    processor.block_number = 1
    request_packet = processor.request_file(file_name)
    client_socket.sendto(request_packet, server_address)
    out_packet = request_packet
    address = server_address
    while not processor.is_done:
        try:
            server_response = client_socket.recvfrom(2048)
            data, address = server_response
            processor.process_udp_packet(data, address)
            out_packet = processor.get_next_output_packet()
            client_socket.sendto(out_packet, address)
        except:
            client_socket.sendto(out_packet, address)
            try:
                server_response = client_socket.recvfrom(2048)
                data, address = server_response
                processor.process_udp_packet(data, address)
                out_packet = processor.get_next_output_packet()
                client_socket.sendto(out_packet, address)
            except:
                processor.is_done = True
                print("Retry later !")


    pass


def parse_user_input(address, operation, file_name=None):

    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.


    if operation == "push":
        _push(address,operation,file_name)
    elif operation == "pull":
        _pull(address,operation,file_name)
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

    ip_address = get_arg(1, input("Enter ip_adress "))
    operation = get_arg(2, input("operation "))
    file_name = get_arg(3, input("file name "))

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
