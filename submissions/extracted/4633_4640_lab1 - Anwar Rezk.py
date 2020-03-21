# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct

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
        self.filename = ""
        self.datalen = 0
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # add the packet to be sent to self.packet_buffer

        # packet_data and packet_source will be output of
        # socket.recvfrom()

        print(f"Received a packet from {packet_source}")

        in_packet = self._parse_udp_packet(packet_data) # Checks for type of packet

        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        if type(out_packet) == bytes:
            self.packet_buffer.append(out_packet)
        

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        
        # Extract the first 2 bytes from packet
        # Ziad to Anwar: (uid,), adv_packet = struct.unpack("!I", adv_packet[:4]), adv_packet[4:]
        # This template updates packet as it unpacks; makes it easier to get file name in case of RRQ and WRQ
        
        in_packet = [] # in_packet to return and do protocol logic on
        (opcode,), packet_bytes = struct.unpack("!H",packet_bytes[:2]), packet_bytes[2:]
        in_packet.append(opcode)
        
        if opcode == TftpProcessor.TftpPacketType.RRQ.value or opcode == TftpProcessor.TftpPacketType.WRQ.value: # Read Request == 1/Write Request == 2
            # Extract file name
                        
            lfname = 0 # Length of file name
            
            for i in range(0,len(packet_bytes)):
                if packet_bytes[i] == 0: # if reached termination char
                    break
                else:
                    lfname += 1
                    
            fname, packet_bytes = packet_bytes[:lfname], packet_bytes[lfname + 1:]
            in_packet.append(fname)
            # Extract mode
            
            mode = packet_bytes[:len(packet_bytes) - 1]
            in_packet.append(mode)
        elif opcode == TftpProcessor.TftpPacketType.DATA.value: # DATA == 3
            (blockno,), packet_bytes = struct.unpack("!H",packet_bytes[:2]), packet_bytes[2:]
            in_packet.append(blockno)
            in_packet.append(packet_bytes)            

        elif opcode == TftpProcessor.TftpPacketType.ACK.value: # ACK == 4
            (blockno,) = struct.unpack("!H",packet_bytes[:2])
            in_packet.append(blockno)
        elif opcode == TftpProcessor.TftpPacketType.ERROR.value: # ERROR == 5
            (errcode,), packet_bytes = struct.unpack("!H",packet_bytes[:2]), packet_bytes[2:]
            in_packet.append(errcode)
            in_packet.append(packet_bytes[:len(packet_bytes) - 1])
            
        return in_packet

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        opcode = input_packet[0]
        
        if opcode == 1: # Client sent an RRQ
            self.filename = ""
            self.datalen = 0
            fname = input_packet[1]
            try:
                with open(fname, "rb") as f:
                    data = f.read()
                # Construct the output packet
                data512 = b''
                for i in range(len(data)):
                    if i == 512:
                        break
                    data512 += data[i:i+1]
                outopcode = 3
                blockno = 1
                out_packet = struct.pack("!HH%ds"%len(data512), outopcode, blockno, data512)
                self.filename  = fname
                self.datalen = len(data512)
            except: # ERROR packet should be sent informing the client that an error with the file has occurred
                outopcode = 5
                errorcode = 1
                errmsg = b'File not found'
                zero = 0
                out_packet = struct.pack("!HH%dsB"%len(errmsg), outopcode, errorcode, errmsg, zero)
        elif opcode == 2: # Client sent an WRQ
            self.filename = ""
            fname = input_packet[1]
            if os.path.exists(fname): # Send error packet because file already exists
                outopcode = 5
                errorcode = 6
                errmsg = b'File already exists'
                zero = 0
                out_packet = struct.pack("!HH%dsB"%len(errmsg), outopcode, errorcode, errmsg, zero)
            else: # Create a new file and send ACK
                self.filename  = fname
                f= open(fname,"wb")
                f.close()
                outopcode = 4
                blockno = 0
                out_packet = struct.pack("!HH",outopcode,blockno)
        elif opcode == 3: # Client sent DATA
            with open(self.filename, "ab") as f:
                f.write(input_packet[2])
            outopcode = 4
            blockno = input_packet[1] # To send ACK
            out_packet = struct.pack("!HH",outopcode,blockno)
        elif opcode == 4: # Client sent an ACK
            blockno = input_packet[1]
            if self.filename == "": # To handle the case when server sends error packet and client sends an ack with block no 1
                return -1
            if self.datalen < 512:
                return -1
            with open(self.filename,'rb') as f:
                f.seek(blockno * 512)
                data = f.read()
            # Construct the output packet
            data512 = b''
            for i in range(len(data)):
                if i == 512:
                    break
                data512 += data[i:i+1]
            outopcode = 3
            blockno += 1
            out_packet = struct.pack("!HH%ds"%len(data512), outopcode, blockno, data512)
            self.datalen = len(data512)
        elif opcode == 5: # Client sent an ERROR
            errorcode = input_packet[1]
            errmsg = input_packet[2]
            print(f'Error : {errmsg} , Code : {errorcode}')
            return -1
        else:
            self.filename = ""
            outopcode = 5
            errorcode = 4
            errmsg = b'Illegal TFTP operation'
            zero = 0
            out_packet = struct.pack("!HH%dsB"%len(errmsg), outopcode, errorcode, errmsg, zero)

        return out_packet

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


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass

# DONE
def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """
    # don't forget, the server's port is 69
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # Creating UDP socket
    sock.bind((address,69)) # Associate socket with a port to receive mesasages
    print(f"TFTP server started on on [{address}]...")
    return sock


def do_socket_logic(sock):
    '''This function will accept a socket as parameter
        and do the stuff'''
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
    # The IP of the server.
    ip_address = get_arg(1, "127.0.0.1")
    sock = setup_sockets(ip_address)
    tftp_proc = TftpProcessor()

    # Socket Logicb
    while True:
        print("Waiting to receive data...")
        data , addr = sock.recvfrom(4096)
        tftp_proc.process_udp_packet(data,addr) # This Should do a lot of stuff :)
        if tftp_proc.has_pending_packets_to_be_sent():
            sock.sendto(tftp_proc.get_next_output_packet(), addr)
        


if __name__ == "__main__":
    main()
