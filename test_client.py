import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ("127.0.0.1", 45002)

# Note that sockets accept data as "bytes"
# Sending a string will fail because the socket
# can't assume an "encoding" that transforms this
# string to the equivalent set of bytes.

# client_socket.sendto("Hello".encode("ascii"), server_address)
# on the other side, the server must call "decode" to convert
# the received bytes to a human readable string.
client_socket.sendto(b"Hello", server_address)
print("[CLIENT] Done!")
# The buffer is the size of packet transit in our OS.
server_packet = client_socket.recvfrom(2048)
print("[CLIENT] IN", server_packet)
