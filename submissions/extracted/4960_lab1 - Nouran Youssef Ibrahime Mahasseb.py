# Don't forget to change this file's name before submission.
import sys
import os
import enum
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

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.file = None
        self.file_data = None
        self.flag= False
        self.l = 0
        self.u = 512
        self.i=1
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

        #print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        if in_packet is None:
            return
        output_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        if output_packet is not None:
            self.packet_buffer.append(output_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """
        if int.from_bytes(packet_bytes[:2], byteorder='big') == 5: # so its an error
            msg = [chr(a) for a in packet_bytes[4:-1]]
            print(''.join(msg))
            self.file.close()

        elif int.from_bytes(packet_bytes[:2], byteorder='big') == 3: # so its a data packet
            self.file.write(packet_bytes[4:])
            return packet_bytes

        elif int.from_bytes(packet_bytes[:2], byteorder='big') == 4: # ack packet , check write block number
            j = self.i - 1
            j2 = int.from_bytes(packet_bytes[2:3], byteorder='big')
            j3 = int.from_bytes(packet_bytes[3:4], byteorder='big')
            if (j2 == (int(j/256)) and (j3 == (j%256))):
                return packet_bytes  # if correct do nothing
            else: # wrong block number
                packet_bytes = bytearray([9,9]) # becomes an illegal operation
                return packet_bytes



        else: # illegal instruction , return error in do_some_logic
            return packet_bytes


    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        if int.from_bytes(input_packet[:2], byteorder='big') == 3:  # now i need to respond with ACK
            if len(input_packet) < 516: # this is last packet
                self.packet_buffer = [] # so it quits
                self.file.close()
                self.flag = True
            input_packet = bytearray(input_packet[:4])
            input_packet[0] = 0
            input_packet[1] = 4
            return input_packet

        elif int.from_bytes(input_packet[:2], byteorder='big') == 4: # it is an acknoledgment , since if error , would be handled in parse_udp , wouldnt reach here
            if self.l>= len(self.file_data):
                self.file.close()
                return None
            data = [0, 3, int(self.i / 256), self.i % 256]
            self.i += 1
            data = bytearray(data)
            data += self.file_data[self.l:self.u]
            self.l += 512
            self.u += 512
            self.packet_buffer.append(data)

        else: # illegal TFTP packet
            self.flag=True # send packet then break
            packet = [0,5,0,4] + [ord(c) for c in 'Illegal TFTP operation.']
            packet = bytearray(packet)
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
        next_packet = self.packet_buffer[0]
        del self.packet_buffer[0]
        return next_packet

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
        down_req = [0, 1] + [ord(c) for c in file_path_on_server] + [0] + [111, 99, 116, 101, 116] + [0]
        down_req = bytearray(down_req)
        self.packet_buffer.append(down_req)
        self.file = open(file_path_on_server.split('/')[-1], 'wb') # in case what given was a path not just file name


    def upload_file(self, file_path):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.
        """
        up_req = [0, 2] + [ord(c) for c in file_path.split('/')[-1]] + [0] + [111, 99, 116, 101, 116] + [0]
        up_req = bytearray(up_req)
        self.packet_buffer.append(up_req)
        self.file = open(file_path, 'rb')  # in case what given was a path not just file name
        self.file_data = self.file.read()

def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass








def parse_user_input(address, operation, file_name=None):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    if operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        Tftp = TftpProcessor()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        Tftp.request_file(file_name)
        address = (address,69)

        while True:
            s.sendto(Tftp.get_next_output_packet(),address)
            data, address = s.recvfrom(516)
            Tftp.process_udp_packet(data,address)
            if not Tftp.has_pending_packets_to_be_sent():
                break # buffer is empty, error happened  , break
            if Tftp.flag: # buffer contains final ack packet send then break , or send error
                s.sendto(Tftp.get_next_output_packet(), address)
                break





    elif operation == "push":
        if not os.path.exists(file_name):
            print("Path does not exist")
            return
        print(f"Attempting to upload [{file_name}]...")
        Tftp = TftpProcessor()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        Tftp.upload_file(file_name)
        address = (address, 69)

        while True:
            s.sendto(Tftp.get_next_output_packet(), address)
            ack, address = s.recvfrom(516)
            Tftp.process_udp_packet(ack, address)
            if not Tftp.has_pending_packets_to_be_sent():
                break  # buffer is empty, error happened  , break or no more packets break
            if Tftp.flag: # sned_error packet
                s.sendto(Tftp.get_next_output_packet(), address)
                break


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
    #print("*" * 50)
    #print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    #print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "push")
    file_name = get_arg(3, "young_man.png")

    # Modify this as needed.
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
