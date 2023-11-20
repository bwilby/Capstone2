import socket
import threading
import struct
import logging
import uuid
from select import select

def client_thread():
    # Ip declarations
    #   Multicast channel
    MCAST_GRP = "239.255.255.250"
    MCAST_PORT = 3702

    # UDP discovery content
    udp = "discovery_response.udp"
    file = open(udp)
    discovery = file.read()

    uuid_value = str(uuid.uuid1())
    print("UUID is: " + uuid_value)
    discovery = discovery.replace('dbd27f63-307e-11ee-bf63-00049f073007', uuid_value)

    # Multicast configuration
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', MCAST_PORT))

    # Adding the socket to multicast group
    mreq = struct.pack("4sL", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print("Listener Thread: waiting to receive multicast udp message...\n")

    while True:
        try:
            #Receive broadcast
            ready = select([sock], [], [], 1)
            if ready[0]:
                data, add = sock.recvfrom(10240)
                data = data.decode('utf-8')
                
                sender_ip, sender_port = add
                print("Heard broadcast from: ")
                print(sender_ip, ", ", sender_port)
                print("------------------------")
                print(data)
                sock.sendto(discovery.encode('utf-8'), (sender_ip, sender_port))

        except Exception as e:
            logging.error(e)
            quit

#   Camera network details

y = threading.Thread(target = client_thread)
y.start()

# Compliant with two client.py changes...

# line 1272, change to {local_ip = socket.gethostbyname(socket.gethostname())}
# line 1004, change to {sock.bind(('', local_port))}

# Must run before client.py or will not receive mulitcast message
