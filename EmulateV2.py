
import socket
import threading
import struct
import logging
import uuid
from select import select
import xml.etree.ElementTree as ET

class userClass:
    def __init__(self, username, password, user_level):
        self.username = username
        self.password = password
        self.user_level = user_level 

def emulator_thread(camera_ip, camera_port, MCAST_GRP, MCAST_PORT):
    udp = "/Users/sadierosenbaum/Downloads/Cap1/viper-ai-camera-tests-master/HTTP_TEST_FILES/discovery_response.udp"

    discovery = read_request(udp).decode('utf-8')

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

                print(f"Heard broadcast from: {add}")
                print("------------------------")
                print(data)

                sock.sendto(discovery.encode('utf-8'), add)
                print(f"send to {add}")
                sock.close()
                print("Discovery udp response has been sent to client")
                print("Initiating TCP listener to discover client")
                tcp_listen(camera_ip, camera_port,add)

        except Exception as e:
            logging.error(e)
            quit

def tcp_listen(camera_ip, camera_port, add):
    # Connect to client tcp request
    emulator_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    emulator_listen.bind((camera_ip, camera_port))
    print("Bind to", camera_ip, camera_port)
    # 127.0.0.2 : 5555
    emulator_listen.listen(1)

    while True:
        try:
            #Receive tcp messages
            ready = select([emulator_listen], [], [], 1)
            if ready[0]:
                conn, addr = emulator_listen.accept()
                data = conn.recv(10240)
                data = data.decode('utf-8')
                print("TCP message received from", addr)
                # Identify what test
                if not identify_test(data, add):
                    print("Invalid test file request")

        except Exception as e:
            logging.error(e)
            quit

def identify_test(data, add) -> bool:
    xml_front = data.index('<?xml version="1.0" encoding="utf-8"?>')
    xml_back = data.index("</soap:Envelope>")
    xml = data[xml_front:xml_back+16]

    # XML namespaces declarations
    xml_namespaces = {'soap': 'http://www.w3.org/2003/05/soap-envelope', 'tds':'http://www.onvif.org/ver10/device/wsdl'}
    xml_test_tags = {'get_users': '{http://www.onvif.org/ver10/device/wsdl}GetUsers','body': '{http://www.w3.org/2003/05/soap-envelope}Body','create_user': '{http://www.onvif.org/ver10/device/wsdl}CreateUsers'}

    root = ET.fromstring(xml)
    root.findall('soap:Body', xml_namespaces)
    check = False
    for node in root:
        # Try to find body node
        if node.tag == xml_test_tags['body']:
            # Try to find create user node
            for section in node:
                if section.tag == xml_test_tags['create_user']:
                    user_data = create_users(data)

                    # Something to append to file that is to be sent to tester client
                    # Generate response file
                    res_file = "HTTP_TEST_FILES/1_dev_mngt_CreateUsers.res"
                    response_file = read_request(res_file)
                    tcp_send(add, response_file)
                    check = True
                elif section.tag == xml_test_tags['get_users']:
                    # Get user test
                    res_file = "HTTP_TEST_FILES/2_dev_mngt_GetUsers.res"
                    response_file = read_request(res_file)
                    tcp_send(add, response_file)
                    check = True
    return check


def tcp_send(add, data):
    sender_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to ", add)
    sender_client.connect(add)
    sender_client.send(data)
    print("Send complete")
    
def read_request(req_file):
    with open(req_file, 'rb') as file:
        return file.read()

#   User creation data test
def create_users(data) -> [userClass]:
    def security_detail(xml):
        # If functionality to test authentication, 
        
        # Public access to namespace key, so hardcoded
        namespaces = {"soap" : "http://www.w3.org/2003/05/soap-envelope"}

        security_string = "Security"
        header_string = "Header"
        username_string = "Username"
        password_string = "Password"
        nonce_string = "Nonce"
        created_string = "Created"
        header_section = "{" + namespaces["soap"] + "}" + header_string

        root = ET.fromstring(xml)
        # First loop to find elements in soap envelope
        for child in root:
            # Then find which header is 
            if child.tag == header_section:
                # Find security section
                for section in child:
                    if security_string in section.tag:
                        for section_child in section:
                            username = None
                            password = None
                            nonce = None
                            created = None
                            for element in section_child:
                                # print(element.tag)
                                if username_string in element.tag:
                                    username = element.text
                                if password_string in element.tag:
                                    password = element.text
                                if nonce_string in element.tag:
                                    nonce = element.text
                                if created_string in element.tag:
                                    created = element.text
                            print(f"Username: {username}\nPassword: {password}\nNonce {nonce}\nCreated: {created}\n")

    def create_user_test(username, password, level) -> userClass:
        # Here would be camera's create user function
        newUser = userClass(username, password, level)
        return newUser
    
    user_database = []

    xml_front = data.index('<?xml version="1.0" encoding="utf-8"?>')
    xml_back = data.index("</soap:Envelope>")
    xml = data[xml_front:xml_back+16]
    
    security_detail(xml)

    # XML namespaces declarations
    xml_namespaces = {'soap': 'http://www.w3.org/2003/05/soap-envelope', 'tds':'http://www.onvif.org/ver10/device/wsdl', 'tt':'http://www.onvif.org/ver10/schema', 's':'http://www.w3.org/2001/XMLSchema'}

    # print(xml)
    root = ET.fromstring(xml)
    root.findall('soap:Body', xml_namespaces)
    for node in root:
        # Try to find body node
        if node.tag == "{http://www.w3.org/2003/05/soap-envelope}Body":
            # Try to find create user node
            for Createuser in node.findall('tds:CreateUsers', xml_namespaces):
                # Iterate through user section
                for users in Createuser:
                    print("Found users\n----------------------")
                    username = users.find('tt:Username', xml_namespaces).text
                    password = users.find('tt:Password', xml_namespaces).text
                    user_level = users.find('tt:UserLevel', xml_namespaces).text
                    print(f"Username: {username}\nPassword: {password}\nUser Level: {user_level}\n----------------------")
                    user_database.append(create_user_test(username, password, user_level))
                    print("Added to database\n")

    # Print database testing
    print("Current users:")
    for index in range(len(user_database)):
        print(user_database[index].username)

    return user_database

# Main

#   Camera IP declaration
camera_ip = "127.0.0.2"
camera_port = 5555

#   Multicast channel
MCAST_GRP = "239.255.255.250"
MCAST_PORT = 3702

y = threading.Thread(target=emulator_thread, args=(camera_ip, camera_port, MCAST_GRP, MCAST_PORT))
y.start()
