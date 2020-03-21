# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct
import binascii

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
    RRQ = 1
    WRQ = 2
    DATA = 3
    ACK = 4
    ERROR = 5

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """

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
        return in_packet



    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        data = ""
        if(packet_bytes[1] == self.DATA):
            # Data packet
            block_number = struct.unpack('>BB', packet_bytes[2:4])
            ACK_packet = self.generate_ACK_packet(block_number)
            return ACK_packet
        elif(packet_bytes[1] == self.ERROR):
            ERR_packet = self.generate_ERR_packet(packet_bytes)

        elif(packet_bytes[1] == self.ACK):
            # ACK_packet = self.generate_DATA_packet(packet_bytes)
            return True
        pass

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """

        
        pass
    
    def generate_RRQ_packet(self,file_name):
        RRQ = list(bytearray([0, 1]))
        file_name = file_name.split("/")
        file_name = file_name[-1]
        file_name  = list(file_name.encode(encoding='UTF-8', errors='strict'))
        RRQ.extend(file_name)
        RRQ.extend([0])
        RRQ.extend("octet".encode(encoding='UTF-8', errors='strict'))
        RRQ.extend([0])
        return bytearray(RRQ)

    def generate_ACK_packet(self,block_number):
        ACK = list(bytearray([0,4]))
        ACK.extend(block_number)
        return bytearray(ACK)


    def generate_ERR_packet(self,packet_byte):
        print("SERVER ERROR:",packet_byte[4:].decode())
        exit(-1)
        pass

    def generate_WRQ_packet(self,file_name):
        WRQ = list(bytearray([0, 2]))
        file_name  = list(file_name.encode(encoding='UTF-8', errors='strict'))
        WRQ.extend(file_name)
        WRQ.extend([0])
        WRQ.extend("octet".encode(encoding='UTF-8', errors='strict'))
        WRQ.extend([0])
        return bytearray(WRQ)

    def generate_DATA_packet(self,data,block_number):
        DATA = list(bytearray([0,3]))
        # DATA.extend([left_index])
        # DATA.extend([right_index])
        block = struct.pack('>H', block_number)
        DATA.extend(block)
        DATA.extend(data)
        # print(bytearray(DATA))
        return bytearray(DATA)

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

    def bytes_from_file(self, filename,chunksize=512):
        try:
            with open(filename, "rb") as f:
                while True:
                    chunk = f.read(chunksize)
                    if chunk:
                        for b in chunk:
                            yield b
                        # return chunk
                    else:
                        break
        except:
            print("File not found")
            exit(-1)

    def open_file(self,filename):
        arr = []
        for b in self.bytes_from_file(filename,512):
            arr.append(b)
        return arr

    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        RRQ = self.generate_RRQ_packet(file_path_on_server)
        return RRQ

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        WRQ = self.generate_WRQ_packet(file_path_on_server)
        return WRQ




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
    client_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    server_address = (address,69)

    return client_sock,server_address
    
def pull(client_socket,data,port,address):
    server_address = (address,port)
    client_socket.sendto(data,server_address)
    packet_data, packet_source = client_socket.recvfrom(4096)
    
    return packet_data,packet_source

def push(client_socket,data,port,address):
    server_address = (address,port)
    client_socket.sendto(data,server_address)
    packet_data, packet_source = client_socket.recvfrom(4096)

    return packet_data,packet_source


def write_output(downloaded_data,file_name):
    with open(file_name, 'w') as f:
            for item in downloaded_data:
                f.write("%s\n" % item)
    pass


def chunks(l, n):
    # For item i in a range that is a length of l,
    for i in range(0, len(l), n):
        # Create an index range for l of n items:
        yield l[i:i+n]

def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code. 
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        p = TftpProcessor()
        file_to_be_uploaded = p.open_file(file_name)
        file_to_be_uploaded = list(chunks(file_to_be_uploaded, 512))
        # print(bytearray(file_to_be_uploaded[2]))
        client_socket,server_address = setup_sockets(address)
        client_ob = TftpProcessor()
        WRQ = client_ob.upload_file((file_name))
        
        packet_data,packet_source = push(client_socket,WRQ,69,address)
        block_number = 0
        

        for b in file_to_be_uploaded:
            next_packet = client_ob.process_udp_packet(packet_data,packet_source)
            if(next_packet == True):
                block_number = block_number+1
                DATA = client_ob.generate_DATA_packet(b,block_number)
                packet_data,packet_source = push(client_socket,DATA,packet_source[1],address)
                
        print("SERVER: Upload Done!")

        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        downloaded_data = []
        client_socket,server_address = setup_sockets(address)
        client_ob = TftpProcessor()
        RRQ = client_ob.request_file(("/var/lib/tftpboot/"+file_name))
        packet_data,packet_source = pull(client_socket,RRQ,69,address)
        downloaded_data.append(packet_data[4:].decode())
        success = False
        if(len(packet_data[4:]) < 512):
            next_packet = client_ob.process_udp_packet(packet_data,packet_source)
        else:
            while(len(packet_data[4:]) == 512):
                next_packet = client_ob.process_udp_packet(packet_data,packet_source)
                packet_data,packet_source = pull(client_socket,next_packet,packet_source[1],address)
                check_if_end = packet_data[4:]
                downloaded_data.append(packet_data[4:].decode())
                success = True
        write_output(downloaded_data,file_name)
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
if __name__ == "__main__":
    main()