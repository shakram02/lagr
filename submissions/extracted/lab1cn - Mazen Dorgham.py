

import socket
import sys

import struct
    class readandwrite:
    def __init__(self,opcode, filename , zeros , stringg , zeross):
        self.opcode = opcode
        self.filename = filename
        self.zeros = zeros
        self.stringg = stringg
        self.zeross = zeross


    class data:
    def __init__(opcode , blockNO,data):
        self.opcode = opcode
        self.blockNO = blockNO
        self.data = data

    class acknowledged :
    def __init__(self, opcode , blockNO):
        self.opcode = opcode
        self.blockNO = blockNO
       

    class error :
    def __init__(self, opcode , errorcode , zero ):
        self.opcode = opcode
        self.errorcode = errorcode
       self.zero = zero


import os
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
        read =1
        write =2 
        data =3
        acknowledged =4
        error = 5

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
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
      if ((packet_bytes[0] == 0)and (packet[1]==3)):
            data=data(packet_bytes[0:1] ,packet_bytes[2:3],packet_bytes[4:515])

    elif  ((packet_bytes[0] == 0)and (packet[1]==4)):
            acknowledged=acknowledged(packet_bytes[0:1] ,packet_bytes[2:3])

    elif  ((packet_bytes[0] == 0)and (packet[1]==5)):
           sys,exit("error message")
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        pass

    def _do_some_logic(self, input_packet):
       global file_name
        """
        Example of a private function that does some logic.
        """
       

        if(type(input_packet) is acknowledged):
          array = self.file_read(file_name)
          message = array.read(512)
          mess = bytes(message)
          print(contents)

          if contents is None:
            print ('fp is at the eof')

          else:
            f = bytes(b'\x00\x03')
            s = input_packet.block_no
            s = int.from_bytes(s, "big")+1
            s = (s).to_bytes(2,byteorder='big')
            print("Entered",contents)
            packet = f + s + contents
          return packet

        elif (type(input_packet) is data):
            f=bytes(b'\x00\x04')
            s=input_packet.block_no
            s = int.from_bytes(u2, "big")+1
            s = (s).to_bytes(2, byteorder='big')
            s = bytes(s)
            acknowledged=f+s
            return acknowledged
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
        pass

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
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
        
       a=bytes(b'\x00\x02')
       b=bytes(file_name.encode("ASCII"))
       c=bytes(b'\x00')    
       d=bytes("octet".encode("ASCII"))
       e=bytes(b'\x00')
       totalpacket=a+b+c+d+e
      return totalpacket
      pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")


        a=bytes(b'\x00\x01')
       b=bytes(file_name.encode("ASCII"))
       c=bytes(b'\x00')    
       d=bytes("octet".encode("ASCII"))
       e=bytes(b'\x00')
       totalpacket=a+b+c+d+e
      return totalpacket
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

   global filename
   client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   serveraddress = ('127.0.0.1',69)
   filename ="networks.txt"
   inp=parse_user_input(serveraddress,"push",filename 
   client_socket.sendto(inp,serveraddress)
   var=TftpProcessor()


   while (true)
     print('RECEIVED FROM')
     Packk,server = client_socket.recvfrom(512)
     new.process_udp_packet(Packk,server)

   if new.has_pending_packet_to_be_sent():
      pack=new.get_next_output_packet()
      pack = bytes(packet) 
      client_socket.sendto(pack,serveraddress)

client_socket.close()




if __name__ == "__main__":
   main()
