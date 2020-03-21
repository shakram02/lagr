# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct
from queue import Queue
import math


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

    def __init__(self,block_size,filename,port):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.block_size = block_size
        self.blocknumber = 0
        self.packet_buffer = []
        self.filename=filename
        self.port=port
        self.loop=0
        self.msg=""
        self.flag=True
        self.done=False
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
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.

        """
        opcode = struct.unpack('!H', packet_bytes[:2])[0]

        if opcode == TftpProcessor.TftpPacketType.ERROR.value:
            res = struct.unpack('!H'.format(len(packet_bytes[2:4])), packet_bytes[2:4])
            res2 = struct.unpack('{}s'.format(len(packet_bytes[4:])), packet_bytes[4:])
            result = []
            result.append("e")
            result.append(res)
            result.append(res2)

        elif opcode == TftpProcessor.TftpPacketType.DATA.value:
            if self.port != 69:
                self.port = 69
            res = struct.unpack('!H'.format(len(packet_bytes[2:4])), packet_bytes[2:4])
            res2 = struct.unpack('{}s'.format(len(packet_bytes[4:])), packet_bytes[4:])
            result = []
            result.append("d")
            result.append(res)
            result.append(res2)

        elif opcode == TftpProcessor.TftpPacketType.ACK.value:
            if self.port != 69:
                self.port = 69
            res = struct.unpack('!H ', packet_bytes[2:4])
            result=[]
            result.append("a")
            result.append(res)

        else:
            raise Exception('Opcode not recognized: %s', str(opcode))
        return result

    def _do_some_logic(self, input_packet):
        """
        server_error_msg = {
                0: "Not defined, see error message (if any).",
                1: "File not found.",
                2: "Access violation.",
                3: "Disk full or allocation exceeded.",
                4: "Illegal TFTP operation.",
                5: "Unknown transfer ID.",
                6: "File already exists.",
                7: "No such user."
            }
        """
        if input_packet[0] == "e":
            packet = input_packet[1][0]
            message = input_packet[2]
            print(message)
            message=bytes(message[0]).decode('utf-8')
            print("Error %s: %s" % (packet,message))
            sys.exit(packet)

        elif input_packet[0] == "d":

            self.blocknumber+=1
            blocknumber = input_packet[1]
            x = int(''.join(map(str, blocknumber)))
            if x != self.blocknumber:
                print('unexpected block num %d' % x)
            print('received ack for %d' % x)
            data=input_packet[2]
            with open("test2.txt", "ab") as filehandle:
                filehandle.write(data[0])
                filehandle.close()

            opcode = TftpProcessor.TftpPacketType.ACK.value
            packet = struct.pack('! H  H', opcode, self.blocknumber)
            return packet

        elif input_packet[0] == "a":
            blocknumber  = input_packet[1]
            x= int(''.join(map(str,blocknumber)))
            self.blocknumber += 1
            print('received ack for %d' % x)
            opcode = TftpProcessor.TftpPacketType.DATA.value
            x=math.ceil(len(self.msg)/511)
            i=1
            if i<x:
                packet = struct.pack('! H H {}s'.format(len(self.msg[self.loop:self.loop+512])), opcode,self.blocknumber,self.msg[self.loop:self.loop+512])
                self.loop=self.loop+512

            else:
                packet = struct.pack('! H H {}s'.format(len(self.msg[self.loop:])), opcode,self.blocknumber, self.msg[self.loop:])
                self.flag=False
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
        self.filename = file_path_on_server
        opcode = TftpProcessor.TftpPacketType.RRQ.value
        packet = struct.pack('! H {}s B {}s B'.format(len(file_path_on_server), len('octet')), opcode,bytes(file_path_on_server, 'utf-8'), 0, bytes('octet', 'utf-8'), 0)
        return packet

    def Readfile(self):
        f=open(self.filename,"rb")
        self.msg=f.read()
        f.close()

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        opcode = TftpProcessor.TftpPacketType.WRQ.value
        packet = struct.pack('! H {}s B {}s B'.format(len(file_path_on_server), len('octet')),opcode, bytes(file_path_on_server, 'utf-8'), 0, bytes('octet', 'utf-8'), 0)
        self.Readfile()
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
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)
    return client_socket,server_address


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

    client_socket,server_address=setup_sockets(address)
    Tftp = TftpProcessor(512, file_name, 69)
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        packet = Tftp.upload_file(file_name)
        client_socket.sendto(packet, server_address)
        print("[CLIENT] Done!")
        data, add = client_socket.recvfrom(4)
        Tftp.process_udp_packet(data, server_address)

        if(Tftp.flag==True):

            while (Tftp.flag==True):

                if (Tftp.has_pending_packets_to_be_sent() == 1):
                    client_socket.sendto(Tftp.get_next_output_packet(), add)
                data, add = client_socket.recvfrom(4)

                if (Tftp.flag==False):
                    Tftp.process_udp_packet(data, server_address)
                    break
                else:
                    Tftp.process_udp_packet(data, server_address)
        else :
            if (Tftp.has_pending_packets_to_be_sent() == 1):
                client_socket.sendto(Tftp.get_next_output_packet(), add)



    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        packet = Tftp.request_file(file_name)
        client_socket.sendto(packet, server_address)
        print("[CLIENT] Done!")
        data, add = client_socket.recvfrom(Tftp.block_size+4)
        if(len(data)>=(Tftp.block_size+4)):
            Tftp.process_udp_packet(data, server_address)

            while (len(data)>=(Tftp.block_size+4)):

                if (Tftp.has_pending_packets_to_be_sent() == 1):
                    client_socket.sendto(Tftp.get_next_output_packet(), add)
                data, add = client_socket.recvfrom(Tftp.block_size+4)

                if(len(data)<(Tftp.block_size+4)):
                    Tftp.done=True
                    Tftp.process_udp_packet(data, server_address)
                    if (Tftp.has_pending_packets_to_be_sent() == 1):
                        client_socket.sendto(Tftp.get_next_output_packet(), add)
                    break
                else :
                    Tftp.process_udp_packet(data, server_address)
        else :
            Tftp.done = True
            Tftp.process_udp_packet(data, server_address)
            if (Tftp.has_pending_packets_to_be_sent() == 1):
                client_socket.sendto(Tftp.get_next_output_packet(), add)





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
 m    if you need the command line arguments
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


if __name__ == "__main__":
    main()