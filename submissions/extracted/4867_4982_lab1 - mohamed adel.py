import os
import socket
import argparse
from pathlib import PurePosixPath, Path
import sys
import os
import enum
import struct
import time
from struct import *

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
        WRQ=2
        DATA=3
        ACK=4
        ERROR=5




    def __init__(self):

        """
        Add and initialize the *internal* fields you need.

        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.

        """
        self.RRQ = 1
        self.WRQ = 2
        self.DATA = 3
        self.ACK = 4
        self.ERROR = 5
        self.packet_buffer = []
        self.byte_data=bytearray()

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

        out_packet = self._do_some_logic(in_packet)



        # This shouldn't change.
        if in_packet[0]==3:
            self.packet_buffer.append(in_packet[2])
        return in_packet

    def _parse_udp_packet(self, packet_bytes):

        if packet_bytes[1]==3:
            f="!hh{}s"
            f=f.format(len(packet_bytes[4::]),len('netascii'))
            str=unpack(f,packet_bytes)
        elif packet_bytes[1]==4:
            str=unpack("!hh",packet_bytes)

        elif packet_bytes[1]==5:
            f="!hh{}sB"
            f = f.format(len(packet_bytes[4:-2]), len('netascii'))
            str=unpack(f,str)
        return str



        pass



    def _do_some_logic(self, input_packet):

        """

        Example of a private function that does some logic.

        """

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



    def request_file(self, file_path_on_server,client_socket,server_address):
        self.byte_data=self.seiralization(file_path_on_server,'RRQ')
        recieved_data,address=do_socket_logic(client_socket,server_address,self.byte_data)
        ret=self.process_udp_packet(recieved_data,address)
        f=open(file_path_on_server,'wb')
        i=0
        while len(recieved_data)==516:
            if ret[0]==3:
                print("Block "+str(i+1)+" downlading")
                f.write(self.get_next_output_packet())
                recieved_data, address = do_socket_logic(client_socket, address,self.seiralization(file_path_on_server,'ACK',ret[1]))
                ret = self.process_udp_packet(recieved_data, address)
                i=i+1
            elif ret[0]==5:
                 error_code=struct.unpack("!bb",recieved_data[2:4])[1]
                 format="!"+str(len(recieved_data[4:len(recieved_data)-1]))+"s"
                 error_msg=struct.unpack(format,recieved_data[4:len(recieved_data)-1])
                 print(error_code,"Message = ",error_msg[0].decode("UTF-8"))
                 break
        print("downLoading done")

        pass



    def upload_file(self, file_path_on_server,client_socket,server_address):
        self.byte_data=self.seiralization(file_path_on_server,'WRQ')
        self.seiralization(file_path_on_server, 'DATA')
        recieved_data,address=do_socket_logic(client_socket,server_address,self.byte_data)
        ret=self.process_udp_packet(recieved_data,address)
        if ret[0] == 4 and ret[1] ==0:
            i=0
            while(self.has_pending_packets_to_be_sent()):
                recieved_data,address = do_socket_logic(client_socket,address, self.get_next_output_packet())
                ret = self.process_udp_packet(recieved_data, address)
                if ret[0]==5:
                 error_code=struct.unpack("!bb",recieved_data[2:4])[1]
                 format="!"+str(len(recieved_data[4:len(recieved_data)-1]))+"s"
                 error_msg=struct.unpack(format,recieved_data[4:len(recieved_data)-1])
                 print(error_code,"Message = ",error_msg[0].decode("UTF-8"))
                 break
                elif ret[0]==4 and ret[1]==int(i+1):
                    print("block " +str(i+1)+ " sent")
                    i=i+1
                    if i>=len(self.packet_buffer):
                        f=0
                    else:
                        print('error')         
        print('Upload Done')







        pass

    def seiralization(self,filename, type,block_num= None):

        if type == "RRQ":
            formatter = '!h{}sB{}sB'
            formatter = formatter.format(len(filename), len('netascii'))
            srt = struct.pack(formatter, self.RRQ, filename.encode(), 0, "octet".encode(), 0)
        elif type == "WRQ":
            formatter='!h{}sB{}sB'
            formatter = formatter.format(len(filename), len('netascii'))
            srt = struct.pack(formatter, self.WRQ, filename.encode(), 0, "octet".encode(), 0)
        elif type == "DATA":
            formatter = '!hh{}s'
            with open(filename,'rb') as f:
                j=1
                while True:
                    d=f.read(512)
                    if not d:
                        break
                    else:
                        formatter = formatter.format(int(len(d)), len('netascii'))
                        self.packet_buffer.append(struct.pack(formatter,self.DATA,int(j),d))
                        j=j+1
                        srt=self.packet_buffer
        elif type=="ACK":
            srt=struct.pack("!hh",self.ACK,block_num)

        return srt
        pass





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





def do_socket_logic(client_socket,server_address,data):
    client_socket.sendto(data,server_address)
    print("[CLIENT] Done!")
    # The buffer is the size of packet transit in our OS.
    server_packet ,new_address= client_socket.recvfrom(516)
    print("[CLIENT] IN", server_packet)
    print("length of recieved paack= ",len(server_packet))
    return server_packet,new_address


    """

    Example function for some helper logic, in case you

    want to be tidy and avoid stuffing the main function.



    Feel free to delete this function.

    """

    pass





def parse_user_input(address, operation,socket,server_socket,file_name=None):

    # Your socket logic can go here,

    # you can surely add new functions

    # to contain the socket code.

    # But don't add socket code in the TftpProcessor class.

    # Feel free to delete this code as long as the

    # functionality is preserved.
    TFTP=TftpProcessor()
    if operation == "push":

        print(f"Attempting to upload [{file_name}]...")
        #do_socket_logic(socket,server_socket,TFTP.byte_data)
        TFTP.upload_file(file_name,socket,server_socket)

        pass

    elif operation == "pull":

        print(f"Attempting to download [{file_name}]...")
        TFTP.request_file(file_name,socket,server_socket)

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
    ui=input() #take user input

    print("*" * 50)

    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))

    check_file_name()

    print("*" * 50)



    # This argument is required.

    # For a server, this means the IP that the server socket

    # will use.

    # The IP of the server, some default values

    # are provided. Feel free to modify them.

    ip_address = get_arg(1, ui.split(' ')[0])

    operation = get_arg(2, ui.split(' ')[1])

    file_name = get_arg(3, ui.split(' ')[3])

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("192.168.1.9", 69)
    client_socket.bind(('', 5555))
    # Modify this as needed.
    parse_user_input(ip_address, operation,client_socket,server_address, file_name)



if __name__ == "__main__":

    main()