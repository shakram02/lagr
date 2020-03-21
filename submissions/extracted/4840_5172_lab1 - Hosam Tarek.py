import socket
import sys
import struct
import sys
import os
import enum


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

    def __init__(self, file_name):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """

        self.packet_buffer = []
        self.file_name = file_name
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
        # packet
        contentSize = len(packet_data) - 4
        dataBA = struct.unpack(">hh" + str(contentSize) + "s", packet_data)
        # Handling Data Packets
        if dataBA[0] == 3:
            ACK = struct.pack(">hh", 4, dataBA[1])
            self.FileWrite(self.file_name, dataBA[2])
            self.packet_buffer.append(ACK)
            return "DATA"

        # Handling Ack Packets
        elif dataBA[0] == 4:
            print("packet acknowledged")
            blockNumber = dataBA[1]

            return blockNumber

        # Handling Error Packets
        elif dataBA[0] == 5:
            dataBA = struct.unpack(">hh" + str(contentSize) + "s", packet_data)
            self.ErrorHandler(dataBA[1], dataBA[2])
            return "ERROR"

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.

        """
        pass

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """

        return input_packet

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
        # Packing RRQ packet
        lFile = str(len(file_path_on_server))
        fNameEncoded = bytes(file_path_on_server, "ascii")
        modEncoded = bytes("octet", "ascii")
        RRQPacket = struct.pack(
            ">h" + lFile + "sb5sb", 1, fNameEncoded, 0, modEncoded, 0
        )
        return RRQPacket

    def FileRead(self):
        # Reading file
        f = open(self.file_name, "rb")
        my_File = f.read()

        arrOfPackets = []
        count = 0

        # Dividing File into Bytes
        while count <= len(my_File):
            arrOfPackets.append(my_File[count : count + 512])
            count = count + 512

        count = 0
        NoOfPackets = len(arrOfPackets)

        # Dividing File into Data packets
        # +Appending to buffer
        while count < NoOfPackets:
            my_String = arrOfPackets.pop(0)
            my_packet_flags = struct.pack(">hh", 3, count + 1)
            my_packet = my_packet_flags + my_String
            self.packet_buffer.append(my_packet)
            count = count + 1

    def upload_file(self, file_path_on_server):
        """
        This method is only valid if you're implementing
        a TFTP client, since the client requests or uploads
        a file to/from a server, one of the inputs the client
        accept is the file name. Remove this function if you're
        implementing a server.

        """
        self.FileRead()
        # Packing WRQ packet
        lFile = str(len(file_path_on_server))
        fileName_in_ASCII = bytes(file_path_on_server, "ascii")
        mode_in_ASCII = bytes("octet", "ascii")
        WRQ = struct.pack(
            ">h" + lFile + "sb5sb", 2, fileName_in_ASCII, 0, mode_in_ASCII, 0,
        )
        return WRQ

    def ErrorHandler(self, ErrCode, ErrMessage):
        if ErrCode == 0:
            print("Not defined," + ErrMessage + ".")
        elif ErrCode == 1:
            print("File not found.")
        elif ErrCode == 2:
            print("Access violation.")
        elif ErrCode == 3:
            print("Disk full or allocation exceeded.")
        elif ErrCode == 4:
            print("Illegal TFTP operation.")
        elif ErrCode == 5:
            print("Unknown transfer ID.")
        elif ErrCode == 6:
            print("File already exists.")
        elif ErrCode == 7:
            print("No such user.")

    def FileWrite(self, fName, packet):
        f = open(fName, "ab+")
        f.write(packet)


def check_file_name():
    script_name = os.path.basename(__file__)

    import re

    matches = re.findall(r"(\d{4,5}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    # Create a UDP socket
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind the socket to the port
    server_address = (address, 69)
    print("starting up on {} port {}".format(*server_address))
    # Set timeout
    sck.settimeout(0.1)
    return sck, server_address


def do_socket_logic(command_type, file_name, my_Socket, my_Server_adr):

    tftpObj = TftpProcessor(file_name)

    # Upload Request
    if command_type == "push":

        # Block Number of Packet sent
        PackNSent = 0

        # Send WRQ Packet
        WRQ = tftpObj.upload_file(file_name)
        my_Socket.sendto(WRQ, my_Server_adr)

        # Waiting For Ack to send another packet
        while tftpObj.has_pending_packets_to_be_sent():
            # Receive Packet
            try:
                packet, address = my_Socket.recvfrom(516)
            except:
                packet = 0

            if not packet:
                print("Something went wrong :( ,Terminating Connection")
                break

            response = tftpObj.process_udp_packet(packet, address)

            # Handling Responses
            if response == PackNSent:
                # Getting the packet to be sent
                PacketTBSent = tftpObj.get_next_output_packet()
                # Unpacking the packet to be sent to get the block number
                contentSize = str(len(PacketTBSent) - 4)
                PacketSentUnPack = struct.unpack(
                    ">hh" + contentSize + "s", PacketTBSent
                )
                PackNSent = PacketSentUnPack[1]
                my_Socket.sendto(PacketTBSent, address)

            elif response == "ERROR":
                my_Socket.close()
                sys.exit()

            elif response == "DATA":
                my_Socket.close()
                sys.exit()

            else:
                print("Packet received unidentified")
        print("Upload Complete")

    # DownLoad Request
    elif command_type == "pull":
        # Send RRQ Packet
        RRQ = tftpObj.request_file(file_name)
        my_Socket.sendto(RRQ, my_Server_adr)

        # Receive File
        while True:
            # Receive Packet
            try:
                data, address = my_Socket.recvfrom(516)
            except:
                data = 0
            if not data:
                my_Socket.close()
                sys.exit()
                break
            # Check if The Packet received is correct
            tftpObj.process_udp_packet(data, address)
            # Send Ack Packet for data packet received
            while tftpObj.has_pending_packets_to_be_sent():
                SendingPacket = tftpObj.get_next_output_packet()
                my_Socket.sendto(SendingPacket, address)

    # Closing Sockets
    my_Socket.close()
    sys.exit()

    pass


def parse_user_input(address, operation, file_name):
    # Your socket logic can go here,
    # you can surely add new functions
    # to contain the socket code.
    # But don't add socket code in the TftpProcessor class.
    # Feel free to delete this code as long as the
    # functionality is preserved.
    my_Socket, my_Server_adr = setup_sockets(address)
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        do_socket_logic("push", file_name, my_Socket, my_Server_adr)
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        do_socket_logic("pull", file_name, my_Socket, my_Server_adr)
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
            print(f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def main():

    my_input = input("Enter your value: ")
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()

    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server, some default values
    # are provided. Feel free to modify them.

    ip_address = get_arg(1, my_input.split(" ")[0])
    operation = get_arg(2, my_input.split(" ")[1])
    file_name = get_arg(3, my_input.split(" ")[2])

    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
