# Don't forget to change this file's name before submission.
import sys
import os
import enum
import struct
import socket


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

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.server_address = ("127.0.0.1", 69)
        self.mode = "octet"
        self.terminate = False
        pass
    #unkown
    def process_udp_packet(self, packet_data, packet_source, databytes = None):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f"Received a packet from {packet_source}")
        #in_packet = self._parse_udp_packet(packet_data)
        #out_packet = self._do_some_logic(in_packet)
        out_packet = self._parse_udp_packet(packet_data, databytes)
        # This shouldn't change.
        self.packet_buffer.append(out_packet)
        pass

    #common
    def _parse_udp_packet(self, packet_bytes,data_bytes): ##parsing file to 512 packets
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        out_packet = bytearray()
        if(packet_bytes[1] == 3):
            print('data')
            block_no_1 = packet_bytes[2]
            block_no_2 = packet_bytes[3]
            print(f'block_no: {block_no_2}, {block_no_1}')
            if(len(packet_bytes) < 516):
                self.terminate = True
            #ack op code
            out_packet.append(0)
            out_packet.append(4)
            #adding block-number
            out_packet.append(block_no_1)
            out_packet.append(block_no_2)
           
            #print(f"output_packet: {out_packet}")
        
        elif(packet_bytes[1] == 4):
             print('Ack')
             block_no_1 = packet_bytes[2]
             block_no_2 = packet_bytes[3]
             block_no_2 += 1
             print(f'block_no Upload: {block_no_2} , {block_no_1} ')
             #data op code
             out_packet.append(0)
             out_packet.append(3)
             #adding block-number
             if(block_no_2 == 256):
                 block_no_1 += 1
                 block_no_2 = 0
             out_packet.append(block_no_1)
             out_packet.append(block_no_2)
             #adding data
             out_packet += data_bytes
             #print(f"output_packet: {out_packet}")

        elif(packet_bytes[1] == 5):
            self._handle_error(packet_bytes[3])
        
        return out_packet

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        pass
    #upload
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
    #upload
    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0
    #download
    def request_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        ##creating the tftp RRQ format
        request = bytearray()
        #opcode for RRQ is 01
        request.append(0)
        request.append(1)
        #converting file name to bytes
        request += bytearray(file_path_on_server.encode("ASCII"))
        #delimiting it by 0
        request.append(0)
        #adding mode
        request += bytearray(self.mode.encode("ASCII"))
        print(f"Request {request}")
        request.append(0)
        return request
    #upload
    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        ##making tftp format##
        request = bytearray()
        #opcode for write 02
        request.append(0)
        request.append(2)
        #file name
        #print(bytearray(file_path_on_server.encode("ASCII")))
        request += bytearray(file_path_on_server.encode("ASCII"))
        # request.append(bytes(file_path_on_server,"ASCII"))
        #then 0
        request.append(0)
        #then modes
        request += bytearray(self.mode.encode("ASCII"))
        #request.append(bytes(self.mode, "ASCII"))
        print(f"Request {request}")
        request.append(0)
        return request
    #common
    def _handle_error(self, error_num):
        #print(error_num)

        switcher = {
            0 : "Not defined, see error message (if any).",
            1 : "File not found.",
            2 : "Access violation.",
            3 : "Disk full or allocation exceeded.",
            4 : "Illegal TFTP operation.",
            5 : "Unknown transfer ID.",
            6 : "File already exists.",
            7 : "No such user.",
        }
        print(switcher.get(error_num, "Invalid error number"))
        exit(-1)    #to terminate the program after printing the error
    

#testing
def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass

#common
def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #Create udp socket
    return client_socket

#common
def do_socket_logic_download(client_socket,request,tf,file):
    """
        Gets the Server packet along with the packet source
        and sends it for further processing to know which operation to be done depending on op-code
    """
    client_socket.sendto(request, tf.server_address)
    serverpacket, address = client_socket.recvfrom(4096)
    print(serverpacket)
    do_file_operation_download(file,serverpacket)
    tf.process_udp_packet(serverpacket,address)
    while tf.has_pending_packets_to_be_sent():
        #print(f"Request to be sent: {request}")
        client_socket.sendto(tf.get_next_output_packet(),address)
        if not tf.terminate:
            serverpacket, address = client_socket.recvfrom(4096)
            tf.process_udp_packet(serverpacket,address)
            do_file_operation_download(file,serverpacket)
        #print(serverpacket)

    file.close()
    pass

def do_socket_logic_upload(client_socket,request,tf,file):
    """
        Gets the Server packet along with the packet source
        and sends it for further processing to know which operation to be done depending on op-code
    """

    client_socket.sendto(request, tf.server_address)
    serverpacket, address = client_socket.recvfrom(4096)
    #print(serverpacket)
    file_bytes = _read_f_arraybytes(file)
    databytes, file_bytes = do_file_operation_upload(file_bytes)
    tf.process_udp_packet(serverpacket, address, databytes)
    while True:
        #print(f"Request to be sent: {request}")
        client_socket.sendto(tf.get_next_output_packet(),address)
        serverpacket, address = client_socket.recvfrom(4096)
        #print(f"Server packets in while {serverpacket}")
        databytes, file_bytes = do_file_operation_upload(file_bytes)   #to get 512 bytes
        if(len(databytes) == 0):
            print("File uploaded completed successfully")
            break
        tf.process_udp_packet(serverpacket, address, databytes)
        if not tf.has_pending_packets_to_be_sent():
            print("SADASDASDASDASDAASDSA")

    file.close()

    pass

def _read_f_arraybytes(filename):
    """read file in array of bytes"""
    return filename.read()


def do_file_operation_download(file,serverpacket):
    if(serverpacket[1] == 3):
        file.write(serverpacket[4:])
    pass

def do_file_operation_upload(file_bytes):
    returnbytes = file_bytes[0 : 512]
    file_bytes = file_bytes[512 : len(file_bytes)]
    return returnbytes, file_bytes
    pass

#common
def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code. 
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    client_socket = setup_sockets(address)
    tf = TftpProcessor()
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        request  = tf.upload_file(file_name)
        file = open(file_name,"rb")
        do_socket_logic_upload(client_socket,request,tf,file)
        print("Upload Complete!")
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        request = tf.request_file(file_name)
        file = open(file_name,"wb")
        do_socket_logic_download(client_socket,request,tf,file)
        print("File downloaded successfully!")

    pass

#common
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
    operation = get_arg(2, "push")
    file_name = get_arg(3, "test.txt")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()