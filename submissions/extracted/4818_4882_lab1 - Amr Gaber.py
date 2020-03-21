# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct


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
        RRQ     = 1
        WRQ     = 2
        DATA    = 3
        ACK     = 4
        ERROR   = 5


    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        # indicate 0 => Starting packet  1 => indicate connected to server
        self.packet_buffer = []
        self.block_number = 0

        self.done = False   # start/stop the Tftp protocol
        self.receive = True # start/stop recieving packets
        self.repeat = False # to send the packet again incase of mismatching

        self.err_code = 0  
        self.err_msg = ""
        
        
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
        opcode =struct.unpack('!H',packet_bytes[:2])[0]

        if opcode == self.TftpPacketType.DATA.value:
            self.block_number = struct.unpack('!H', packet_bytes[2:4])[0]
            self.fd.write(packet_bytes[4:])
            if len(packet_bytes) < (512+4):
                self.fd.close()
                self.done = True
                self.receive = False

        elif opcode == self.TftpPacketType.ACK.value:
            block_number = struct.unpack('!H',packet_bytes[2:4])[0]
            self.repeat = not (self.block_number == block_number)

        elif opcode == self.TftpPacketType.ERROR.value:
            _ = self.raise_err(int(struct.unpack('!H', packet_bytes[2:4])[0]))
            
        return opcode


    def _do_some_logic(self, input_packet):
        """
        Used to make a packet that will be put inside the buffer.
        """

        if input_packet == self.TftpPacketType.ACK.value:
            data = self.fd.read(512)
            # check if it is the final data packet
            if len(data) < 512:
                self.done = True

            # check if there was a mismatch in a data packet to ask for it again
            if self.repeat:
                packet = struct.pack('!HH', self.TftpPacketType.DATA.value, self.block_number) + data

            # get the next data packet
            else:
                self.block_number += 1
                packet = struct.pack('!HH', self.TftpPacketType.DATA.value, self.block_number) + data

        elif input_packet == self.TftpPacketType.DATA.value:
            packet = struct.pack('!HH', self.TftpPacketType.ACK.value, self.block_number)

        # if error, terminate the connection
        elif input_packet == self.TftpPacketType.ERROR.value:
            sys.exit()

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

        # check before sending a request if the file already exists
        exists = os.path.exists(file_path_on_server)
        if exists:
            return self.raise_err(6)
            
        try: 
            self.fd=open(file_path_on_server, 'wb')
            mode = b'octet'
            opcode = self.TftpPacketType.RRQ.value
            file_path_on_server = file_path_on_server.encode('ascii')
            packet = struct.pack('!H{}sB{}sB'.format(len(file_path_on_server), len(mode)), opcode, file_path_on_server, 0, mode, 0)
        except:  # incase access violation 
            packet = self.raise_err(2)

        return packet
        

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """

        try:
            self.fd = open(file_path_on_server, 'rb')
            mode = b'octet'
            opcode = self.TftpPacketType.WRQ.value
            file_path_on_server = file_path_on_server.encode('ascii')
            packet = struct.pack('!H{}sB{}sB'.format(len(file_path_on_server), len(mode)), opcode, file_path_on_server, 0, mode, 0)
        except:
            exists = os.path.exists(file_path_on_server)
            if not exists:  # incase file not found   
                packet = self.raise_err(1)
            else: # incase access violation 
                packet = self.raise_err(2)
        return packet
    
    
    def raise_err(self,err_code):
        """
        This method is for handling errors and
        stopping the Tftp protocol and receiving packets
        """
        self.err_code = err_code
        self.done = True
        self.receive = False

        if err_code == 0:
            self.err_msg = b"Not defined, see error message (if any)."

        elif err_code == 1:
            self.err_msg = b"File not found."
        elif err_code == 2:
            self.err_msg = b"Access violation."
        elif err_code == 3:
            self.err_msg = b"Disk full or allocation exceeded."
        elif err_code == 4:
            self.err_msg = b"Illegal TFTP operation."
        elif err_code == 5:
            self.err_msg = b"Unknown transfer ID."
        elif err_code == 6:
            self.err_msg = b"File already exists."
        elif err_code == 7:
            self.err_msg = b"No such user."

        print("Error Happened code : ",self.err_code ,"Message : ", self.err_msg.decode('ascii'))  

        packet = struct.pack('!HH{}sB'.format(len(self.err_msg)), self.TftpPacketType.ERROR.value, self.err_code,self.err_msg, 0)
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


def do_socket_logic(process,address,request_packet):
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    C_socket, C_server = setup_sockets(address)

    if request_packet:
        C_socket.sendto(request_packet, C_server)
        if process.receive:
            packet, rev_addr = C_socket.recvfrom((512+4))
        
    while not process.done: 
        process.process_udp_packet(packet, rev_addr)
        if process.has_pending_packets_to_be_sent():
            C_socket.sendto(process.get_next_output_packet(), rev_addr)
            if process.receive:
                packet, rev_addr = C_socket.recvfrom((512+4))
    

def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code. 
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.

    process = TftpProcessor()

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        request_packet = process.upload_file(file_name)
        print("back")
        do_socket_logic(process, address,request_packet)
    
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        request_packet = process.request_file(file_name)
        do_socket_logic(process, address,request_packet)

    else: # incase of illegal tftp operation
       do_socket_logic(process, address,process.raise_err(4)) 


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
