import sys
import os
import enum
import socket
import struct
import math
class TftpProcessor(object):
    """
    Implements logic for a TFTP server.
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
    cll_address=0

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

        #out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        #self.packet_buffer.append(out_packet)
    def read_upload(self ,filename,client_address):
        

        server_socket = setup_sockets()
        try:
            file = open(filename , "rb")    
    
        except:
            str="File not found."
            error=bytearray(b'\x00\x05\x00\x01')+str.encode()+b'\x00'
            server_socket.sendto(error,self.cll_address)
            exit(1)
            
        
        fileDate = file.read(512)
        while len(fileDate) != 0 :
            self.packet_buffer.append(fileDate)
            fileDate = file.read(512)
        opCode=3
        blckNum=1
        while self.has_pending_packets_to_be_sent():
            packet=struct.pack("!HH",opCode,blckNum)
            packet=packet+self.get_next_output_packet()
            server_socket.sendto(packet,client_address)
            packet = server_socket.recvfrom(520)
            pacOp,pacAdd=packet
            opcode=pacOp[0:2]
            intOpcode=int.from_bytes(opcode,byteorder='big')
            if intOpcode > 0 and intOpcode < 4 or intOpcode > 4 and intOpcode < 6:
                str="Illegal TFTP operation."
                error=bytearray(b'\x00\x05\x00\x04')+str.encode()+b'\x00'
                server_socket.sendto(error,self.cll_address)
                exit(1)
            elif intOpcode == 0 or intOpcode > 5 :
                str="Not defined"
                error=bytearray(b'\x00\x05\x00\x00')+str.encode()+b'\x00'
                server_socket.sendto(error,self.cll_address)
                exit(1)
            blckNum=blckNum+1
        
        
        

        return 0



    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        
        server_socket = setup_sockets()
        opcode=packet_bytes[0:2]
        intOpcode=int.from_bytes(opcode,byteorder='big')
        
         
        
        if intOpcode == 1 :
            data=packet_bytes.split(b'\0')
            fileName=data[1][1:].decode("utf-8")
            mode=data[2]
            blksize =int (data[4])
            filesize =int(data[6])
        
            self.read_upload(fileName,self.cll_address) 


        elif intOpcode == 2:
            data=packet_bytes.split(b'\0')
            fileName=data[1][1:].decode("utf-8")
            mode=data[2]
            blksize =int (data[4])
            filesize =int(data[6])
            numberOfblocks = math.ceil (filesize / blksize)
            self.write_download(numberOfblocks,fileName)
        elif intOpcode > 2 and intOpcode < 6:
            str="Illegal TFTP operation."
            error=bytearray(b'\x00\x05\x00\x04')+str.encode()+b'\x00'
            server_socket.sendto(error,self.cll_address)
            exit(1)
        elif intOpcode==0 or intOpcode > 5 :
            str="Not defined"
            error=bytearray(b'\x00\x05\x00\x00')+str.encode()+b'\x00'
            server_socket.sendto(error,self.cll_address)
            exit(1)
        pass
        return 0

    def write_download(self, numberOfblocks,fileName):
        """
        Example of a private function that does some logic.
        """
        server_socket = setup_sockets()
        os_chosen_one= server_socket.getsockname()
        server_ip,server_port=os_chosen_one
        if os.path.isfile(fileName):
            str="File already exists."
            error=bytearray(b'\x00\x05\x00\x06')+str.encode()+b'\x00'
            server_socket.sendto(error,self.cll_address)
            exit(1)
        sent_file=open(fileName,"wb")
        ack=4
        for i in range(0 ,numberOfblocks):
            packet=struct.pack("!HH",ack,i)
            server_socket.sendto(packet,self.cll_address)
            ans=server_socket.recv(server_port)
            opcode=ans[0:2]
            intOpcode=int.from_bytes(opcode,byteorder='big')
            if intOpcode > 3 and intOpcode < 6 or intOpcode > 0 and intOpcode < 3:
                str="Illegal TFTP operation."
                error=bytearray(b'\x00\x05\x00\x04')+str.encode()+b'\x00'
                server_socket.sendto(error,self.cll_address)
                exit(1)
            elif intOpcode == 0 or intOpcode > 5 :
                str="Not defined"
                error=bytearray(b'\x00\x05\x00\x00')+str.encode()+b'\x00'
                server_socket.sendto(error,self.cll_address)
                exit(1)
            sent_file.write(ans[4:])

        pass
        return 0
    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.
        For example;
        s_socket.send(tftp_processor.get_next_output_packet())
        Leave this function as is.
        """
        return    self.packet_buffer.pop(0)
    

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.
        
        Leave this function as is.
        """
        return len(self.packet_buffer) != 0


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets():
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("127.0.0.1", 0)
    server_socket.bind(server_address)
    return server_socket
    pass


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
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
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Note that this address must be specified in the client.
    server_address = ("127.0.0.1", 69)

    # Bind tells the OS to allocate this address for this process.
    # Clients don't need to call bind since the server doesn't
    # care about their address. But clients must know where the
    # server is.
    server_socket.bind(server_address)
    print("[SERVER] Socket info:", server_socket)
    print("[SERVER] Waiting...")
    # This line of code will "Block" the execution of the program.
    packet = server_socket.recvfrom(520)
    data, client_address = packet
    
    print("[SERVER] IN", data)
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server.
    ip_address = get_arg(1, "127.0.0.1")
    AA=TftpProcessor()
    AA.cll_address=client_address
    AA.process_udp_packet(data,client_address)

if __name__ == "__main__":
    main()