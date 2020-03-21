
""" //////////////////////////////////////////////////
                TFTP CLIENT IMPLEMENTATION
    ////////////////////////////////////////////////// """

""" ////////////////////
        INSTRUCTIONS
    //////////////////// """

""" Built Using PyCharm """
""" Testing done by TFTPd64 Software """
""" Create a Server Directory and assign it to tftpd64 """
""" Then start to send and receive between the project directory """
""" And the server directory using this syntax: 127.0.0.1 [push/pull] [filename].[extension] """

""" ///// CODE SKELETON IS PROVIDED BY COMPUTER NETWORKS COURSE TEACHING ASSISTANTS ///// """

""" TOTAL USED FUNCTIONS = 13 """
""" TOTAL UNUSED FUNCTIONS = 4 """

""" ///////////////////////////////////////////////////////////////////////////////////////////// """
""" ///////////////////////////////////////////////////////////////////////////////////////////// """


""" IMPORTS & GLOBAL VARIABLES """
import sys
import os
import enum
import socket
from struct import pack

""" UDP Socket Define """
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = 0

class TftpProcessor(object):

    # Finished
    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    # Finished
    def __init__(self):
        self.packet_buffer = []
        pass

    # Unused
    def process_udp_packet(self, packet_data, packet_source):

        """
        N.B
        I used the concept of processing packet
        Inside the Do_Socket_Logic Function
        And I request and upload files using the specified Functions
        For those operations normally, and I build the Packet
        And the Acknowledgement in two external separate functions.
        """

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    # Finished
    def _parse_udp_packet(self, operation, filepath, data):

        packed = ""
        strn = ""
        if operation == "pull":
            strn = '\0' + chr(1) + filepath + '\0octet\0blksize\0512\0tsize\0' + \
                   '0' + '\0timeout\010\0'

            packed = pack(str(len(strn)) + 's', bytes(strn, 'utf-8'))
            pass
        elif operation == " push":
            # strn = '\0' + chr(2) + filepath + '\0octet\0blksize\0512\0tsize\0' + \
            #        str(len(data)) + '\0timeout\010\0'
            #
            # packed = pack(str(len(strn)) + 's', bytes(strn, 'utf-8'))

            """ There is a problem here if I worked with this function in the Push Operation """

            pass
        return packed
        pass

    # Unused
    def _do_some_logic(self, input_packet):

        pass

    # Unsed
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

    # Unused
    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.
        Leave this function as is.
        """
        return len(self.packet_buffer) != 0

    # Finished
    def request_file(self, file_path_on_server):
        """
        Send RRQ
        """
        message = self._parse_udp_packet("pull", file_path_on_server, None)
        print(message)
        output = open(file_path_on_server, 'wb+')
        arr = [message, output]

        return arr

        pass #

    # Finished
    def upload_file(self, file_path_on_server):
        """
        Upload_file to send WRQ
        """
        f = open(file_path_on_server, "rb")
        fdata = f.read()

        strn = '\0' + chr(2) + file_path_on_server + '\0octet\0blksize\0512\0tsize\0' + \
               str(len(fdata)) + '\0timeout\010\0'

        message = pack(str(len(strn)) + 's', bytes(strn, 'utf-8'))
        #message = self._parse_udp_packet("push", file_path_on_server, fdata)

        return  message
        pass

# Finished
def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+Lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass

# Finished
def do_socket_logic(operation, filename, address):
    tftp = TftpProcessor()  # Processor Instance

    if operation == "push":
        message  = tftp.upload_file(filename)
        flag = 0
        f2 = open(filename, "rb")

        #print(message)
        packetNr = 0
        send = sock.sendto(message, address)
        print('waiting to receive...')
        (data, (address)) = sock.recvfrom(512)
        #print(data)
        while True:
            opcode = data[1]
            if opcode == tftp.TftpPacketType.ERROR.value:  # Error
                print('Error accured: '+Error(data[3]))
                flag = 1
                break
            elif opcode == 4 and (((data[2] << 8) & 0xff00) | data[3]) == packetNr:
                packetNr += 1
                message = DataPacket(packetNr, f2.read(512))
                sock.sendto(message, address)
                """ Use The Next Line If You Want To Print The Number Of Packets/Iteration """
                # print("Packet Number: " + str(packetNr))
                pass
            if(len(message) < 516):
                break
            else:
                (data, (address)) = sock.recvfrom(512)

        if (flag == 0):
            print("*" * 50)
            print('Your Process Is Completed Please Check Your File')
            pass
        else:
            print("*" * 50)
            print('Due To Error Your Process Has Not Completed')
            pass
        pass

    elif operation == "pull":
        packetNr = 1
        arr = tftp.request_file(filename)
        message = arr[0]
        flag = 0

        #print(message)
        send = sock.sendto(message, address)
        print('waiting to receive...')
        (data, (address)) = sock.recvfrom(516)
        #print(data)
        output = arr[1]
        while True:
            opcode = data[1]
            if opcode == tftp.TftpPacketType.ERROR.value:  # Error
                print('Error accured: '+Error(data[3]))
                flag = 1
                break
            elif ((((data[2] << 8) & 0xff00) | data[3]) == packetNr):
                output.write(data[4:])
                msg2 = AckPacket(packetNr)
                packetNr += 1
                sock.sendto(msg2, address)
                """ Use The Next Line If You Want To Print The Number Of Packets/Iteration """
                #print("Packet Number: " + str(packetNr))
                pass
            if (len(data) < 516):
                break
            else:
                (data, (address)) = sock.recvfrom(516)

                # if 512 used instead of 516 this error occur
                # OSError: [WinError 10040] A message sent on a datagram socket was larger than the internal message buffer or some other network limit, or the buffer used to receive a datagram into was smaller than the datagram itself

        output.close()

        if (flag == 0):
            print("*" * 50)
            print('Your Process Is Completed Please Check Your File')
            pass
        else:
            print("*" * 50)
            print('Due To Error Your Process Has Not Completed')
            pass
        pass

    pass

# Finished
def parse_user_input(address, operation, filename):
    if operation == "push":
        print(f"Attempting to upload [{filename}]...")
        do_socket_logic(operation, filename, address)
        pass
    elif operation == "pull":
        print(f"Attempting to download [{filename}]...")
        do_socket_logic(operation, filename, address)
        pass

# Finished
def get_arg(param_index, default=None):
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

""" External Function That Create DATA Packet """
# Finished
def DataPacket(blockNr, Arr):
    tftp = TftpProcessor()
    print("New Packet created!")
    ret = bytearray(4 + len(Arr))
    ret[0] = 0
    ret[1] = tftp.TftpPacketType.DATA.value
    ret[2] = ((blockNr >> 8) & 0xff)
    ret[3] = (blockNr & 0xff)
    for p in range(4, len(Arr) + 4):
        ret[p] = Arr[p-4]
    return ret

""" External Function That Create ACKnowledgement Packet """
# Finished
def AckPacket(blockNr):
    tftp = TftpProcessor()
    print("New Acknowlegde created!")
    ret = bytearray(4)
    ret[0] = 0
    ret[1] = tftp.TftpPacketType.ACK.value
    ret[2] = ((blockNr >> 8) & 0xff)
    ret[3] = (blockNr & 0xff)
    return ret

""" External Function To Handle Errors """
# Finished
def Error(i):
    switcher={
        0: 'Not defined, see error message (if any)',
        1: 'File not found',
        2: 'Access violation',
        3: 'Disk full or allocation exceeded',
        4: 'Illegal TFTP operation',
        5: 'Unknown transfer ID',
        6: 'File already esxists',
        7: 'No such user'
    }
    return switcher.get(i, "error")

# Finished
def main():
    print("=" * 50)
    print(" " * 14 + "*** TFTP CLIENT ***")
    print("=" * 50)
    print("=" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("=" * 50)

    command = input("Enter your Command: ")
    ip_address = get_arg(1, command.split(' ')[0])
    operation = get_arg(2, command.split(' ')[1])
    file_name = get_arg(3, command.split(' ')[2])

    server_address = (ip_address, 69)

    parse_user_input(server_address, operation, file_name)

if __name__ == "__main__":
    main()
