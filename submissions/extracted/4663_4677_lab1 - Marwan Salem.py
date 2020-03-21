# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct
import time

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
        # tftp supports 5 packet types,with corresponding opodes should be two bytes
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
        # define port, but should 
        #self.zz = TftpPacketType.RRQ
        opcode = TftpProcessor.TftpPacketType.RRQ
        
        #print('RES',TftpProcessor.TftpPacketType.RRQ == 1)
        #print('RES2',TftpProcessor.TftpPacketType.WRQ == 2)
        #print(isinstance(1,TftpProcessor.TftpPacketType))
        self.port = 69 ### 69 for the server not for client!
        self.root_path = '//'
        self.client_address = None
        self.client_port = 0
        self.file_path = ''
        self.file_block_count = 0
        self.last_block_num = 0 # takes 2 bytes 
        
        self.fail = False
        self.sent_last = False
        self.ignore_current_packet = False #ignore it if received packet's source is adifferent prot no
        self.tftp_mode = 'octet' # i choose it as default mode or whatever
        self.request_mode = None # 'RRQ' or 'WRQ'
        self.server_address = ('127.0.0.1', 69)
        self.file_bytes = []
        self.reached_end = False
        # self.client_socket = None, WRONG!
        self.packet_buffer = []
        

    def process_udp_packet(self, packet_data, packet_source):#is packet source an adress or what
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        #print(f"Received a packet from {packet_source}")
        #print('rec:',packet_data)
        self.ignore_current_packet = False
        in_packet = self._parse_udp_packet(packet_data)
        if self.ignore_current_packet: # do no add current packet to packet buffer
            return 
        out_packet = self._do_some_logic(in_packet)
        if out_packet == []: # last packet in file acknowledged
            return 
        # This shouldn't change.
        #print('sending:',out_packet)
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):# is it a byte or bytearray?
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        # format = '!H'
        # src_port = struct.unpack('!H', packet_bytes[0:2])[0]
        # if src_port != self.client_port:#ignore stray packets
        #     self.ignore_current_packet = True
        #     return 0
        # dest_port = struct.unpack('!H', packet_bytes[2:4])[0]
        # len = struct.unpack('!H', packet_bytes[4:6])[0]
        # checksum = struct.unpack('!H', packet_bytes[6:8])[0]
        
        return packet_bytes
    
    def _generate_error_packet(self,error_code, error_message=''):
        # error packet format 2bytes opcode(5), 2 bytes error code, error_msg, a 0byte at the end
        error_packet = struct.pack('!HH',TftpProcessor.TftpPacketType.ERROR.value, error_code)
        error_packet += struct.pack('!{}sB'.format(len(error_message)), error_message.encode(), 0)

        return error_packet
    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        # input_packet is the data bytes in the udp packet
        opcode = struct.unpack('!H', input_packet[0:2])[0]
        packetTypes = { 1: 'RRQ', 2:'WRQ', 3:'DATA', 4:'ACK', 5:'ERROR'}
        curr_pack_type = packetTypes[opcode]
        filename = ''
        try:
            packet_type = TftpProcessor.TftpPacketType(opcode)
        except ValueError:# Illegal TFTP operation means illegal opcode!
            self.reached_end = True
            err_msg = 'Illegal TFTP OPERATION'
            print(err_msg)
            # return ERROR Packet with opcode = 5, error code = 4, error message encoded, and a 0 byte
            return self._generate_error_packet(error_code=4, error_message=err_msg)
            #struct.pack('!HH', 5, 4) + struct.pack('!{}sB'.format(len(err_msg)), err_msg.encode(), 0)

        if packet_type == TftpProcessor.TftpPacketType.RRQ or packet_type == TftpProcessor.TftpPacketType.WRQ: 
            #Handle common logic between rrq packet  and write request packet
            #clear file bytes
            self.file_bytes = []
            self.request_mode = packetTypes[opcode]
            seperator_idx = 2 + input_packet[2:].find(0) 
            # get 'end' index of the filename field, which the is the index of the first zero in the sub list after the opcode
            # + 2 because the index returned from find is relative to the sublist ,start index 2:
            filename_bytes = input_packet[2:seperator_idx]
            
            fmt_str = '!{}s'.format(len(filename_bytes))
            #unpack the bytes and get the file_path from the tuple
            self.file_path = struct.unpack(fmt_str, filename_bytes)[0]
            #forbidden access to server files!
            if str(self.file_path, encoding='ascii') == os.path.basename(__file__):
                self.reached_end = True
                self.fail = True
                return self._generate_error_packet(error_code = 0, error_message="Access Forbidden")
            
            # mode is always ascii encoded 
            self.tftp = str(input_packet[seperator_idx+1:-1], 'ascii').lower()
            #print(self.tftp_mode)
        
        if packet_type == TftpProcessor.TftpPacketType.ACK and self.sent_last: # last packet acknowledged
            
            self.sent_last = False
            #end of transmission
            self.reached_end = True
            #return some known value so process_udp_ function knows what to do 
            return []

        if packet_type == TftpProcessor.TftpPacketType.RRQ: ##RRQ
            err = self.read_file() # returns True if the file doesnt exist on the server
            if err:
                ## error code =1 ,, opcode for error = 5
                # form the error packet
                
                err_msg = 'File not found.'
                
                self.reached_end = True
                print(err_msg)
                return self._generate_error_packet(error_code = 1, error_message= err_msg)
            
            
        if packet_type == TftpProcessor.TftpPacketType.WRQ :##WRQ
            #reply with acknowledge with block num = 0  if file doesnt exist on server
            if os.path.exists(self.file_path):# check if file exists on the server already
                error_code = 6
                err_msg = 'File already exists'
                self.reached_end = True
                print(err_msg)
                return self._generate_error_packet(error_code = error_code, error_message= err_msg)

            out_packet = struct.pack('!HH',TftpProcessor.TftpPacketType.ACK.value,0)
        elif packet_type == TftpProcessor.TftpPacketType.DATA :# Data
            #print('in',input_packet)
            block_num = struct.unpack('!H', input_packet[2:4])[0]
            
            if len(input_packet) > 4:#last data packet can have 0 bytes in data
                len_data = len(input_packet[4:])
                if len_data != 512:
                    self.sent_last = True
                    self.reached_end = True
                if self.tftp_mode == 'octet':
                    fmt_str = '!{}B'.format(len_data)
                else: # netascii
                    fmt_str = '!{}s'.format(len_data)
                unpacked_data_bytes = struct.unpack(fmt_str, input_packet[4:])
        
                #print('db',len(unpacked_data_bytes),'--', unpacked_data_bytes)
                #'append' the bytes of the received block to the file bytes so they can be written after end of transmission
                self.file_bytes.extend(unpacked_data_bytes)
            else: #reached end of transmission
                self.reached_end = True
            
            out_packet = struct.pack('!HH',TftpProcessor.TftpPacketType.ACK.value , block_num)
            
        elif packet_type == TftpProcessor.TftpPacketType.ERROR:
            self.reached_end = True
            err_msg = 'Not defined :' + str(input_packet[4:-1],encoding='ascii')
            print(err_msg)
            # return ERROR Packet with opcode = 5, error code = 0, error message encoded, and a 0 byte
            return self._generate_error_packet(error_code=0, error_message=err_msg )
            #struct.pack('!HH', 5, 0) + struct.pack('!{}sB'.format(len(err_msg)), err_msg.encode(), 0)

        if packet_type == TftpProcessor.TftpPacketType.ACK or packet_type == TftpProcessor.TftpPacketType.RRQ:
            # reply to RRQ with first block, and ACK with other blocks
            if packet_type == TftpProcessor.TftpPacketType.RRQ:
                block_num = 1
            else:
                block_num = struct.unpack('!H',input_packet[2:4])[0] + 1
            #print('bno',block_num)
            # get data block after the one in the acknowledge packet , or the first 1 if its a rrq
            data_blocks = self.get_next_data_block(block_num)
        
            len_data = len(data_blocks)    
            if len_data > 0:# check if data is not empty( there are stil blocks to send)
                format_char = ''
                if self.tftp_mode == 'octet':
                    format_char = '!B'
                elif self.tftp_mode == 'netascii':
                    format_char = '!s'
                ### data_blocks convert to required data type
                out_packet = struct.pack('!HH', TftpProcessor.TftpPacketType.DATA.value, block_num)
                for byte in list(data_blocks):
                    out_packet += struct.pack(format_char, byte)
            else:# if file size %512 == 0 then last data packet will have no data blocks
                out_packet = struct.pack('!HH',TftpProcessor.TftpPacketType.DATA.value, block_num  )
            #print('outdata:',out_packet)
        return out_packet

    def ignore_current(self):
        return self.ignore_current_packet
    
    def get_next_data_block(self, block_num):
        # index the file blocks array, since block number starts with 1, so subtract 1
        start_idx = (block_num-1) * 512
        end_idx = start_idx + 512
        
        if end_idx > (self.file_block_count ):# if last block is less than 512 
            # end of transmission
            self.sent_last = True
            #self.reached_end = True
            return self.file_bytes[start_idx :]
        elif end_idx == self.file_block_count: #send empty data block in the end(End of Transmission) if file size is multiple of 512
            self.sent_last = True
            return []
        return self.file_bytes[start_idx: end_idx]


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
    def save_file(self):
        if not self.fail:
            with open(self.file_path, 'wb') as up_file:
                up_file.write(bytes(self.file_bytes))
        
    def read_file(self):
        try:
            with open(self.file_path, 'rb') as f:
                self.file_bytes = list(f.read())
                self.file_block_count = len(self.file_bytes)
            return False
        except FileNotFoundError:# file doesnt exist return True to signify an error happened
            return True


    def get_request_mode(self):
        return self.request_mode

    def transmission_ended(self):#returns True if the last block transmitted
        return self.reached_end
    
    def set_client_address(self, client_address):
        self.client_address = client_address
        #client port needed for checking stray packets
        self.client_port =  client_address[1]#client address is a tuple of ip and port number
    def get_file_path(self):
        return str(self.file_path, encoding='ascii')
    def get_file_size(self):
        return len(self.file_bytes)
    
        


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
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.bind(address)
    return my_socket


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
    # Modify this as needed.
    #parse_user_input(ip_address, operation, file_name)
    ip_address = get_arg(1, "127.0.0.1")
    server_address = (ip_address, 69)
    server_socket = setup_sockets(server_address)
    
    
    print('Server started at',server_address)
    while True: #change it to while after debugging
        print('Waiting for a connection...')
        tftp_proc = TftpProcessor()
        # get a packet containging request line( RRQ or WRQ)
        request_packet ,client_address = server_socket.recvfrom(2048)
        #filepath could be the largest block in a packet, so the packet cant be bigger than 2048 bytes
        tftp_proc.set_client_address(client_address)
        print('Connected to ', client_address)
        #print('REQUEST pack:', request_packet)
        tftp_proc.process_udp_packet(request_packet, client_address)
        request_mode = tftp_proc.get_request_mode()
        
        
        if request_mode == 'RRQ' or request_mode == 'WRQ':
            
            
            while tftp_proc.has_pending_packets_to_be_sent() :# keep sending the 'buffered' packets
                # send response packet to previously received packet
                
                next_packet = tftp_proc.get_next_output_packet()
                server_socket.sendto(next_packet,client_address)
                
                if not tftp_proc.transmission_ended():# receive the next packet if you did not reach the end of transmission
                    
                    received_packet ,received_client = server_socket.recvfrom(2048)
                    #print('PROCESSING')
                    tftp_proc.process_udp_packet(received_packet, received_client)
                    
                    
                else:
                    print('TRANSMISSION ENDED')
                while tftp_proc.ignore_current():# if stray packet received then ignore it get another packet
                    received_packet ,received_client = server_socket.recvfrom(2048)
                    tftp_proc.process_udp_packet(received_packet, received_client)
            #print(tftp_proc.file_bytes)
            print('file path on server:', tftp_proc.get_file_path())
            print(tftp_proc.get_file_size(), ' bytes transmitted ')
            
            if request_mode == 'WRQ':
                # save file after receving the file
                tftp_proc.save_file()
            

        else:
            print('ERROR!')
        #sleep to make client happy
        time.sleep(1)



    



if __name__ == "__main__":
    main()
