import sys
import os
import enum
import socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # intializing a UDP socket


def setup_sockets(address, packet):
    client_socket.sendto(packet, address)
    print("[CLIENT] Done!")
    data, server = client_socket.recvfrom(4096)
    print("[CLIENT] in!")
    return list(data), server




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
        return packet_bytes[1]
        pass

    def _do_some_logic(self, DATA_no, input_packet):
        """
        Example of a private function that does some logic.
        """
        DATA_packet=bytearray()
        DATA_packet.append(0)
        DATA_packet.append(3)
        pstr= format(DATA_no,'b')
        while len(pstr) < 16:
            pstr = '0'+pstr
        DATA_packet.append(int(pstr[0:8],2))
        DATA_packet.append(int(pstr[8:16],2))
        DATA_packet += bytes(input_packet)
        return DATA_packet

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

    def request_file(self, file_path_on_server,pack,block1,block2):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        if pack == 1:
            mode = "octet"
            file = file_path_on_server.encode(encoding='UTF-8', errors='strict')
            RRQ_packet = bytearray()
            RRQ_packet.append(0)
            RRQ_packet.append(1)
            RRQ_packet += bytes(file)
            RRQ_packet.append(0)
            mod = mode.encode(encoding='UTF-8', errors='strict')
            RRQ_packet += bytes(mod)
            RRQ_packet.append(0)
            return RRQ_packet
        elif pack==2:
            ACK_packet=bytearray()
            ACK_packet.append(0)
            ACK_packet.append(4)
            ACK_packet.append(block1)
            ACK_packet.append(block2)
            return ACK_packet







    def upload_file(self,file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """

        mode = "octet"
        file = file_path_on_server.encode(encoding='UTF-8', errors='strict')
        WRQ_packet = bytearray()
        WRQ_packet.append(0)
        WRQ_packet.append(2)
        WRQ_packet += bytes(file)
        WRQ_packet.append(0)
        mod = mode.encode(encoding='UTF-8', errors='strict')
        WRQ_packet += bytes(mod)
        WRQ_packet.append(0)
        return WRQ_packet
        pass


OBJ = TftpProcessor()


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def parse_user_input(address, operation, file_name=None):
    DATA_no=1
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        WRQ_packet=OBJ.upload_file(file_path_on_server=file_name)
        op_code,server=setup_sockets((address, 69),WRQ_packet)
        pack_no=OBJ._parse_udp_packet(packet_bytes=op_code)
        if(pack_no==4):
            try :
                with open(file_name, "rb") as f:
                  while True:
                      chunk = f.read(512)
                      DATA_packet= OBJ._do_some_logic(DATA_no,chunk)
                      op_code,server = setup_sockets(server, DATA_packet)
                      pack_no = OBJ._parse_udp_packet(packet_bytes=op_code)
                      if (len(chunk) < 512):
                          break
                      if not pack_no == 4:
                            print("ERROR")
                            break
                      DATA_no=DATA_no+1
                      if not chunk:
                          break
                client_socket.close()
                print("Upload completed")
            except FileNotFoundError:
                print("File NOT found")
        else:
            print("Else Error")
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        RRQ_packet=OBJ.request_file(file_path_on_server=file_name,pack=1,block1=None,block2=None)
        op_code,server=setup_sockets((address, 69),RRQ_packet)
        pack_no=OBJ._parse_udp_packet(packet_bytes=op_code)
        if(pack_no==3):
                f = open("test.txt", "ab")
                while (True):
                 f.write(bytes(op_code[4:]))
                 ACK_packet = OBJ.request_file(file_path_on_server=file_name, pack=2,block1=op_code[2],block2=op_code[3])
                 op_code, server = setup_sockets(server, ACK_packet)
                 pack_no = OBJ._parse_udp_packet(packet_bytes=op_code)
                 if (pack_no == 5):
                     print("Error")
                 if (len(op_code) < 516):
                     f.write(bytes(op_code[4:]))
                     break
                f.close()
                client_socket.close()
                print("Download completed")
        elif pack_no==5 :
            print("File Not Found on Server")



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