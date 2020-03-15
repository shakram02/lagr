import socket
# Make a new socket object.
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Note that this address must be specified in the client.
server_address = ("127.0.0.1", 32500)

# Bind tells the OS to allocate this address for this process.
# Clients don't need to call bind since the server doesn't
# care about their address. But clients must know where the
# server is.
server_socket.bind(server_address)
print("[SERVER] Socket info:", server_socket)
print("[SERVER] Waiting...")
# This line of code will "Block" the execution of the program.
packet = server_socket.recvfrom(4096)
data, client_address = packet
print("[SERVER] IN", data)
