# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct



BUFFER_SIZE = 65536
BLOCK_SIZE = 512
PORT = 69
TIMEOUT = 1
MAX_RETRIES = 5

    
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
        Represents a TFTP packet type.
        """
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5
        
    class TftpErrorType(enum.Enum):
        """
        Represents a TFTP error type.
        """
        NOT_DEFINED = 0
        FILE_NOT_FOUND = 1
        ACCESS_VIOLATION = 2  
        DISK_FULL = 3         
        ILLEGAL_OPERATION = 4
        UNKOWN_TID = 5
        FILE_ALREADY_EXISTS = 6
        NO_SUCH_USER = 7
    
    class TftpPacket(object):
        """
        Represents TFTP packet.
        this can be refactored into parent and children classes of different
        packet types, then using a factory design pattern to add some abstraction.
        """
        
        def __init__(self):
            self.dbytes = None
            self.opcode = None
            self.mode = "octet"
            self.data = None
            self.block_number = None
            self.file_name = None
            self.error_code = None
            self.error_message = None
            # Default mode here is octet so length of mode is always 5
            self.formats = {
                TftpProcessor.TftpPacketType.RRQ.value:    '!H%dsx5sx',
                TftpProcessor.TftpPacketType.WRQ.value:    '!H%dsx5sx',
                TftpProcessor.TftpPacketType.DATA.value:   '!HH%ds',
                TftpProcessor.TftpPacketType.ACK.value:    '!HH',
                TftpProcessor.TftpPacketType.ERROR.value:  '!HH%dsx',  
            }
        
        def set_params(self, opcode = None, dbytes = None, data = None,
                       block_number = None, file_name = None, error_code
                       = None, error_message = None):
            self.opcode = opcode
            self.dbytes = dbytes
            self.data = data
            self.block_number = block_number
            self.file_name = file_name
            self.error_code = error_code
            self.error_message = error_message
            if self.dbytes != None:
                (self.opcode,) = struct.unpack("!H", self.dbytes[:2])
        
        def encode(self):
            """
            Encodes the params into bytes to be sent.
            set_params should be called first.
            raise an exception if opcode None ?
            """
            if self.opcode == TftpProcessor.TftpPacketType.RRQ.value or \
            self.opcode == TftpProcessor.TftpPacketType.WRQ.value:
                return struct.pack(self.formats[self.opcode]%
                                     (len(self.file_name)), self.opcode,
                                     self.file_name.ecnode("utf-8"),
                                     self.mode.encode("utf-8"))
            elif self.opcode == TftpProcessor.TftpPacketType.DATA.value:
                 return struct.pack(self.formats[self.opcode]%
                                     (len(self.data)), self.opcode,
                                     self.block_number,
                                     self.data)
            elif self.opcode == TftpProcessor.TftpPacketType.ACK.value:
                 return struct.pack(self.formats[self.opcode], self.opcode,
                                     self.block_number)
           
            elif self.opcode == TftpProcessor.TftpPacketType.ERROR.value:
                 return struct.pack(self.formats[self.opcode]%
                                     (len(self.error_message)), self.opcode,
                                     self.error_code,
                                     self.error_message.encode("utf-8"))
        def decode(self):
            """
            Decodes the bytes array into variables
            raise an exception if dbytes None ?
            """
            if self.opcode == None and self.dbytes != None:    
                (self.opcode,) = struct.unpack("!H", self.dbytes[:2])
            if self.opcode == TftpProcessor.TftpPacketType.RRQ.value or \
            self.opcode == TftpProcessor.TftpPacketType.WRQ.value:
                msg = self.dbytes[2:]
                file_name_size = 0
                for i, c in enumerate(msg):
                    if c == 0 or c == '\x00':
                        file_name_size = i
                        break
                unpacked_data = struct.unpack(self.formats[self.opcode]%
                                     (file_name_size),self.dbytes)
                self.opcode = unpacked_data[0]
                self.file_name = unpacked_data[1].decode()
            elif self.opcode == TftpProcessor.TftpPacketType.DATA.value:
                 unpacked_data = struct.unpack(self.formats[self.opcode]%
                                     (len(self.dbytes) - 4), self.dbytes)
                 self.opcode = unpacked_data[0]
                 self.block_number = unpacked_data[1]
                 self.data = unpacked_data[2]
            elif self.opcode == TftpProcessor.TftpPacketType.ACK.value:
                 unpacked_data = struct.unpack(self.formats[self.opcode], self.dbytes)
                 self.block_number = unpacked_data[1]
           
            elif self.opcode == TftpProcessor.TftpPacketType.ERROR.value:
                #'!HH%dsx', 
                unpacked_data = struct.unpack(self.formats[self.opcode]%
                                     (len(self.dbytes) - 5), self.dbytes)
                self.error_code = unpacked_data[1]
                self.error_message = unpacked_data[2].decode()
                
            
        

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.finished = False
        self.current_file = None
        self.EOF_reached = False
        self.current_block = -1
        self.error = False
        self.last_packet = None
        pass
    
    def is_finished(self):
        return self.finished
    
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
        out_packet = self._tftp_logic(in_packet)
        if out_packet != None:
            # This shouldn't change.
            self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        tftp_packet = TftpProcessor.TftpPacket()
        tftp_packet.set_params(dbytes = packet_bytes)
        tftp_packet.decode()
        return tftp_packet



    def _check_if_file_exist(self, file_name):
        return os.path.exists(file_name)
    
    
    def _tftp_logic(self, input_packet):
        """
        A function that process the received packet and returns the reply packet.
        """
        
        if input_packet.opcode == TftpProcessor.TftpPacketType.RRQ.value:
            # should check if the file required to download available or not
            # return a DATA/ERROR packet.
                
            return self._handle_RRQ(input_packet)
            
        elif input_packet.opcode == TftpProcessor.TftpPacketType.WRQ.value:
            # should check if the file already exist ?
            # return a ACK/ERROR packet.
            
            return self._handle_WRQ(input_packet)
        elif input_packet.opcode == TftpProcessor.TftpPacketType.DATA.value:
            # should check if the block number is the right one.
            # return a ACK/ERROR packet.
            
            return self._handle_DATA(input_packet)    
        elif input_packet.opcode == TftpProcessor.TftpPacketType.ACK.value:
            # prepare to send the next DATA packet maybe ? or if EOF ?
        
            return self._handle_ACK(input_packet)
        
        elif input_packet.opcode == TftpProcessor.TftpPacketType.ERROR.value:
            # should terminate if error ?
            
            return self._handle_ERROR(input_packet)
        else:
            # unknown request, None ?
            print(f"unknown request type: {input_packet.opcode}")
            return self._get_error_packet(TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.value, TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.name)    
    
    def _handle_RRQ(self, input_packet):
        already_exists = self._check_if_file_exist(input_packet.file_name)
        print(f"Handling RRQ, file-name: {input_packet.file_name}, exist = {already_exists}")
        if already_exists != True:
            # set error flag ? return error packet file should exist
            print(f"File does not exist, file: {input_packet.file_name}")
            self.finished = True
            self.error = True
            return self._get_error_packet(TftpProcessor.TftpErrorType.FILE_NOT_FOUND.value, TftpProcessor.TftpErrorType.FILE_NOT_FOUND.name)
        
        if self.current_file != None:
            # cannot send RRQ/WRQ after already sending one.
            print(f"Illegal operation!")
            self.finished = True
            self.error = True
            return self._get_error_packet(TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.value, TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.name)
            
        self.current_file = open(input_packet.file_name, "rb")
        data_buffer = self.current_file.read(BLOCK_SIZE)
        if len(data_buffer) < BLOCK_SIZE:
            print(f"Reached EOF, file: {input_packet.file_name}, length: {len(data_buffer)}")
            self.EOF_reached= True
            self.current_file.close()
        self.current_block = 1
        out_packet = TftpProcessor.TftpPacket()
        out_packet.set_params(data= data_buffer, opcode= TftpProcessor.TftpPacketType.DATA.value,
                              block_number= self.current_block)
        
        return out_packet.encode()
    
    def _get_error_packet(self, error_code, msg):
        packet = TftpProcessor.TftpPacket()
        packet.set_params(opcode = TftpProcessor.TftpPacketType.ERROR.value,
                          error_code = error_code, error_message = msg)
        return packet.encode()
        
    
    def _handle_ACK(self, input_packet):
        if input_packet.block_number != 0 and input_packet.block_number == self.current_block - 1:
            # last ack, my new data packet is lost, so client resend his ack ?
            return self.last_packet
        
        if input_packet.block_number != self.current_block:
            # wrong block number, unexpected ACK.
            print(f"received an unexpected block-number, expected: {self.current_block}, received: {input_packet.block_number}")
            return self._get_error_packet(TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.value, TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.name) 
        
        if self.current_file == None:
            # cannot send RRQ/WRQ after already sending one.
            print(f"Illegal operation!")
            self.finished = True
            self.error = True
            return self._get_error_packet(TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.value, TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.name)
        
        
        if(self.EOF_reached):
            self.finished = True
            print("Finished sending the file successfully...")
            return None
        data_buffer = self.current_file.read(BLOCK_SIZE)
        if len(data_buffer) < BLOCK_SIZE:
            self.EOF_reached= True
            self.current_file.close() 
        self.current_block += 1
        out_packet = TftpProcessor.TftpPacket()
        out_packet.set_params(data = data_buffer, opcode= TftpProcessor.TftpPacketType.DATA.value,
                              block_number= self.current_block)
        return out_packet.encode()
   
    
    def _handle_WRQ(self, input_packet):
        already_exists = self._check_if_file_exist(input_packet.file_name)
        print(f"Handling WRQ, file-name: {input_packet.file_name}, exist = {already_exists}")
        if already_exists :
            # set error flag ? return error packet file should exist
            print(f"File already exists, file: {input_packet.file_name}")
            self.error = True
            self.finished = True
            return self._get_error_packet(TftpProcessor.TftpErrorType.FILE_ALREADY_EXISTS.value, TftpProcessor.TftpErrorType.FILE_ALREADY_EXISTS.name)

        if self.current_file != None:
            # cannot send RRQ/WRQ after already sending one.
            print(f"Illegal operation!")
            self.finished = True
            self.error = True
            return self._get_error_packet(TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.value, TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.name)
        
        self.current_file = open(input_packet.file_name, 'wb')
        self.current_block = 0
        out_packet = TftpProcessor.TftpPacket()
        out_packet.set_params(opcode= TftpProcessor.TftpPacketType.ACK.value,
                              block_number= self.current_block)
        return out_packet.encode()
    
    def _handle_DATA(self, input_packet):
        print(f"Handling DATA, block-number: {input_packet.block_number}, length: {len(input_packet.data)}")
        self.current_block += 1
        if input_packet.block_number != self.current_block:
            # error unexpected block number.
            print(f"received an unexpected block-number, expected: {self.current_block}, received: {input_packet.block_number}")
            return self._get_error_packet(TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.value, TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.name) 
        
        if len(input_packet.data) > 512:
            # error unexpected data length (malformed packet ?).
            print(f"received an unexpected data length, expected: <= 512, received: {len(input_packet.data)}")
            return self._get_error_packet(TftpProcessor.TftpErrorType.NOT_DEFINED.value, TftpProcessor.TftpErrorType.NOT_DEFINED.name) 
       
        if self.current_file == None:
            # cannot send RRQ/WRQ after already sending one.
            print(f"Illegal operation!")
            self.finished = True
            self.error = True
            return self._get_error_packet(TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.value, TftpProcessor.TftpErrorType.ILLEGAL_OPERATION.name)
        
        
        
        self.current_file.write(input_packet.data)
        out_packet = TftpProcessor.TftpPacket()
        out_packet.set_params(opcode= TftpProcessor.TftpPacketType.ACK.value,
                              block_number= self.current_block)
        
        if len(input_packet.data) < 512:
            self.EOF_reached = True
            self.finished = True
            self.current_file.close()
            print("Finished receiving the file successfully...")
        return out_packet.encode()
        
    
    def _handle_ERROR(self, input_packet):
        print(f"Received error message: {input_packet.error_message}")
        self.error = True
        self.finished = True
        return None
    
    
    def get_last_packet(self):
        return self.last_packet
    
    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.

        For example;
        s_socket.send(tftp_processor.get_next_output_packet())

        Leave this function as is.
        """
        self.last_packet = self.packet_buffer.pop(0)
        return self.last_packet

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

class TftpServer(object):
    
    def __init__(self, host: str):
        """
        :param host: ip to bind to
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, PORT))
        self.host = host
    
    def listen(self):
        """
        Main server loop to keep listening for messages.
        """
        print(f"TFTP server started on on [{self.host}]...")
        while True:
            data, address = self.sock.recvfrom(BUFFER_SIZE)
            tftp_client_handler = TftpClientHandler(data, address, self.host)
            tftp_client_handler.handle()
        self.sock.close()
        
class TftpClientHandler(object):
    
    def __init__(self, data, address, host):
        """
        :param host: ip to bind to
        :param data: first message from the client to handle
        :param host: address of the client
        
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(TIMEOUT)
        self.sock.bind((host, 0))
        self.host = host
        self.client_address = address
        self.first_message = data
    
    def handle(self):
        """
        Main loop to keep listening for messages.
        """
        print(f"Handling connection with {self.client_address}, at: {self.sock.getsockname()} [{self.host}]")
        tftp_processor = TftpProcessor()
        while True:
            if tftp_processor.is_finished():
                break
            if self.first_message == None:
                  retries_count = 0
                  while retries_count <= MAX_RETRIES:
                      try:
                          data, address = self.sock.recvfrom(BUFFER_SIZE)
                          break
                      except socket.timeout as e:
                          print(f"Socket timeout: {retries_count+1}, {e}")
                          retries_count += 1
                          if retries_count <= MAX_RETRIES:
                              self._send_packet(tftp_processor.get_last_packet(), self.client_address)
                  if retries_count > MAX_RETRIES:
                      print(f"Timeout reached, retried {MAX_RETRIES} times, terminating connection with {self.client_address}...")
                      break
            else:
                data = self.first_message
                address = self.client_address
            
            self.first_message = None
            # Ignore messages from different addresses?
            if self.client_address != address:
                continue
            
            tftp_processor.process_udp_packet(data, address)
            if tftp_processor.has_pending_packets_to_be_sent():
                out_packet = tftp_processor.get_next_output_packet()
                self._send_packet(out_packet, address)
        
        self.sock.close()
    
    def _send_packet(self, out_packet, out_address):
        self.sock.sendto(out_packet, out_address)

     
def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
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
    server = TftpServer(ip_address)
    server.listen()
    #setup_sockets(ip_address)


if __name__ == "__main__":
    main()
