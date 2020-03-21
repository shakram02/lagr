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
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERR = 5
    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.expected = 1
        self.complete = False
        self.packet_buffer = []
        self.file_path = None
        self.file_buffer = []
        self.counter = 0

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

        opcode = int.from_bytes(packet_bytes[0:2], byteorder='big', signed=False)
        print('Opcode : ',opcode)
        packet_type = self.TftpPacketType(opcode)
        seperator = bytearray()
        seperator.append(0)

        if packet_type == self.TftpPacketType.WRQ:
            frames = packet_bytes[2:].split(seperator)
            print(frames)
            filename = frames[0]
            mode = frames[1]
            bytes = frames[2]
            return [ packet_type,filename,mode,bytes]
        elif packet_type == self.TftpPacketType.DATA:
            blockID = int.from_bytes(packet_bytes[2:4], byteorder='big', signed=False)
            print('Frame ID : ',blockID)
            if blockID != self.counter+1:
                print('Error Wrong Block Num')
                print(self.error_packet(5,'Wrong Block Num'))
                return [99,self.error_packet(5,'Wrong Block Num')]
            self.counter = self.counter +1
            frames = packet_bytes[4:].split(seperator)
            #print(frames)
            data = frames[0]
            #print(data)
            print('size of data',len(data))
            if len(data)<512:
                self.complete = True
                print('Done')

            return [packet_type,blockID,data,len(data)]
        elif packet_type == self.TftpPacketType.ACK:
            blockID = int.from_bytes(packet_bytes[2:4], byteorder='big', signed=False)
            print('ACK rec for ',blockID)
            return [packet_type,blockID]

        elif packet_type == self.TftpPacketType.ERR:
            print('Error !')

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        if input_packet == None:
            return
        if(input_packet[0]==self.TftpPacketType.DATA):
            ack_frame = bytearray()
            ack_frame.append(0)
            ack_frame.append(4)

            blockID = bytearray(struct.pack('h', input_packet[1]))
            blockID.reverse()
            ack_frame = ack_frame + blockID
            downloaded = open(self.file_path, "ab")
            data =  bytearray( input_packet[2] )
            downloaded.write(data)
            return ack_frame
        elif input_packet[0]==self.TftpPacketType.ACK:
            data_frame = bytearray()
            data_frame.append(0)
            data_frame.append(3)
            blockID = bytearray(struct.pack('h', input_packet[1]+1))
            blockID.reverse()
            data_frame = data_frame + blockID
            try:
                print('sending ', input_packet[1],' len ',len(self.file_buffer[input_packet[1]]))
                print(self.file_buffer[input_packet[1]])
                data = bytearray( self.file_buffer[input_packet[1]])
                data_frame = data_frame + data
                print('data_frame  = ',len(data_frame))
                return data_frame
            except:
                return None
        elif input_packet[0]  == 99 :
            return input_packet[1]

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
    def operation_complete(self):
        return self.complete
    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        self.complete = False
        self.file_path = file_path_on_server
        downloaded = open(self.file_path, "wb")
        downloaded.write(bytearray(0))
        frame = bytearray()
        frame.append(0)
        frame.append(1)
        for c in (file_path_on_server).encode('utf-8'):
            frame.append(c)
        frame.append(0)
        for c in ("octet").encode('utf-8'):
            frame.append(c)
        frame.append(0)
        self.packet_buffer.append(frame)

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        self.file_path = file_path_on_server
        print('here')
        import os.path

        if not os.path.isfile(file_path_on_server):
            print('Error')
            self.packet_buffer.append(self.error_packet(1,'File not Found'))
            return
        f = open(file_path_on_server, "rb")
        while 1:
            data = f.read(512)
            if data == None:
                return
            self.file_buffer.append(data)
            if  len(data)<512:
                break

        frame = bytearray()
        frame.append(0)
        frame.append(2)
        for c in (file_path_on_server).encode('utf-8'):
            frame.append(c)
        frame.append(0)
        for c in ("octet").encode('utf-8'):
            frame.append(c)
        frame.append(0)
        self.packet_buffer.append(frame)
    def error_packet(self,code,msg):
        error_frame = bytearray()
        error_frame.append(0)
        error_frame.append(5)
        error_frame.append(0)
        error_frame.append(code)
        for i in bytes(msg, 'utf-8'):
            error_frame.append(i)
        error_frame.append(0)
        return  error_frame


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
    server_address = (address, 69)
    local_address = ("127.0.0.1", 19199)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.bind(local_address)
    return client_socket

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
    server_address = (address, 69)
    return_address = server_address
    client_socket = setup_sockets(address)
    print(client_socket)

    myTftpProcessor = TftpProcessor()

    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")

        myTftpProcessor.upload_file(file_name)
        while myTftpProcessor.has_pending_packets_to_be_sent():
            output = myTftpProcessor.get_next_output_packet()
            if output == None:
                return
            client_socket.sendto(output,return_address)
            if not myTftpProcessor.operation_complete():
                server_packet, return_address = client_socket.recvfrom(2048)
                #print(server_packet)
                print('ret add',return_address)
                myTftpProcessor.process_udp_packet(server_packet,return_address)

    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")

        myTftpProcessor.request_file(file_name)

        while myTftpProcessor.has_pending_packets_to_be_sent():
            output = myTftpProcessor.get_next_output_packet()
            if output == None:
                return
            client_socket.sendto(output,return_address)
            if not myTftpProcessor.operation_complete():
                server_packet, return_address = client_socket.recvfrom(2048)
                #print(server_packet)
                print('ret add',return_address)
                myTftpProcessor.process_udp_packet(server_packet,return_address)


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
    # will use.#
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "pull")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)
    exit()

if __name__ == "__main__":
    main()