import socket
import os
import sys

TFTP_OPCODES_Struct = {

    'read': 1,  # RRQ
    'write': 2,  # WRQ
    'data': 3,  # DATA
    'ack': 4,  # ACKNOWLEDGMENT
    'error': 5}  # ERROR
RRQ = 1
TFTP_MODES_Struct = {
    'netascii': 1,
    'octet': 2,
    'mail': 3}


class TFTPErrorCodes:
    """Class containing all the error codes and their messages used in TFTP."""
    UNKNOWN = 0
    FILE_NOT_FOUND = 1
    ACCESS_VIOLATION = 2
    DISK_FULL = 3
    ILLEGAL_OPERATION = 4
    UNKNOWN_TRANSFER_ID = 5
    FILE_EXISTS = 6
    NO_SUCH_USER = 7
    INVALID_OPTIONS = 8

    __MESSAGES = {
        UNKNOWN: '',
        FILE_NOT_FOUND: 'File not found',
        ACCESS_VIOLATION: 'Access violation',
        DISK_FULL: 'Disk full or allocation exceeded',
        ILLEGAL_OPERATION: 'Illegal TFTP operation',
        UNKNOWN_TRANSFER_ID: 'Unknown transfer ID',
        FILE_EXISTS: 'File already exists',
        NO_SUCH_USER: 'No such user',
        INVALID_OPTIONS: 'Invalid options specified',
    }
chunk_array=[]
def has_pending_packets_to_be_sent(self):
    """
    Returns if any packets to be sent are available.
    Leave this function as is.
    """
    return len(self.packet_buffer) != 0
def socket_setup(packets):
    import socket
    import sys

    # Create a UDP socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    server_address = ('localhost', 69)
    message = bytes(packets[0], 'utf-8')

    try:

        # Send data
        print('sending {!r}'.format(message))
        sent = sock.sendto(message, server_address)

        # Receive response
        print('waiting to receive')

        data, server = sock.recvfrom(512)

        print('received {!r}'.format(data))
    except ConnectionResetError:
      print('An error occurred.')
    finally:
        print('Closing socket')
        sock.close


def request_file(self, file_path_on_server):
    data = self.sock.recv(1024)
    f = open('newfile.webm', 'wb')
    while data != bytes('.encode()'):
        data = self.sock.recv(1024)
        f.write(data)
        pass


packet_buffer.append();
pass

def write_file():

    f = open("test.txt", "w+")
    for i in range(100):
        f.write("This is line %d" % (i + 1))
        f.close

def read_file(filename):
    f = open(filename, 'r')
    i = 0
    chunck_array = []
    while True:
        # read a single line
        line = f.read(512)
        chunck_array.append(line)

        if not line:
            break

        i = i+1
        return chunck_array

    # close the pointer to that file
    f.close()






write_file()
socket_setup(read_file("test.txt"))