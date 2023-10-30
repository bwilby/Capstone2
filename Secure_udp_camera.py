import rsa
import random
import socket
import sys
import argparse
import struct
from threading import Thread
import threading
import time
import select
import base64
import uuid
import json
import hashlib
import select
import aes
from datetime import datetime, date, timedelta
import datetime
import security
import messages
import constants
import queue



class secure_udp_camera():

    # PRIV_KEY = None
    # PUB_KEY = None
    # MASTER_PUBKEY = None



    # BROKER_LIST = { 'CA' : [('192.168.0.6',5939),('192.168.0.6',5939),('192.168.0.6',5939)] , 'US' : [('192.168.0.6',5939),('192.168.0.6',5939),('192.168.0.6',5939)] }



    # ENCRYPTION FUNCTIONS

    # Global Vars
    portsList=[] # array to store used ports
    ## ON BOOT ##
    UDP_PORT_NUMBER = 5000
    UDP_CAMERA_PORT = 5001


    ###

    def __init__(self):
        self.SERIAL = '00626E4E3B9811'#'ABC-123-1234-5-66'#'1231-123134-992920-22'
        self.COUNTRY_CODE = 'CA'
        self.VERSION_NUM = '1.3'
        self.DATE_OF_MANUFACTURE = '12/15/2022'  # mm/dd/yyyy
        self.t = 1
        self.DELTA = 0

        self.THREAD_LOCK = threading.Lock()
        self.RECEIVE_CONDITION = threading.Condition()
        self.SEND_CONDITION = threading.Condition()

        self.UDP_SEND_LOCK = threading.Lock()

        # Packets Dict
        self.packet_list = []  # [[id,[date,fragments]]...]
        self.count = False


    def generate_session(self):
        return str(uuid.uuid1())

    def generate_passcode(self):
        return str(random.randint(10000, 100000))

    # Generates a unique port
    def generate_port(self):
        while True: #just does one instance of random
            r=random.randint(10000,65000)
            if r not in secure_udp_camera.portsList: #checks if port number is repeated if not add to list
                secure_udp_camera.portsList.append(r)
                break
        return secure_udp_camera.portsList[-1]

    # Gets Broker from constants file
    def get_broker(self,country_code, i):
        if len(constants.BROKER_LIST[country_code]) > i:
            return constants.BROKER_LIST[country_code][i]
        else:
            return None

    # Gets fragment from Packets Dictionary
    def get_fragment(self,transaction_id, index):
        for packet in self.packet_list:
            if packet[0] == transaction_id:
                return packet[1][1][index]
        print("Fragment does not exist")


    # Handle Commands sent from device and return required data, Not yet implemented
    def udp_com_thread_handle_data(self,dcr_data):
        # decrypted data including the return AES Key + IV
        aes_key = dcr_data[0:32]  # not yet implemented
        aes_iv = dcr_data[32:48]  # not yet implemented
        #return "HELLO THIS IS THE RESULT HEELLLLLLLOOOOOTHIS IS THE RESULT HEELLLLLLLOOOOOTHIS IS THE RESULT HEELLLLLLLOOOOOTHIS IS THE RESULT HEELLLLLLLOOOOOTHIS IS THE RESULT HEELLLLLLLOOOOOTHIS IS THE RESULT HEELLLLLLLOOOOOTHIS IS THE RESULT HEELLLLLLLOOOOOTHIS IS THE RESULT HEELLLLLLLOOOOOTHIS IS THE RESULT HEELLLLLLLOOOOOTHIS IS THE RESULT".encode()
        return bytearray(65507-15) + bytearray(65507-40) + "HEELLLLLLLOOOOOTHIS IS THE RESULT*****".encode() + "HEELLLLLLLOOOOOTHIS IS THE RESULT".encode()

    # Starts a thread that handles communication with a device
    def udp_com_thread(self,UDP_PORT_NUMBER, peer_address, priv_key, preferred_send_date, PREFERRED_UDP_PORT = None, end_state=False):

        try:

            #sock.connect(peer_address)  ##even with UDP connect forces it to only receive from this server address
            conn_est = False
            print("In self.udp_com_thread...starting comm on port:",
                  UDP_PORT_NUMBER, " connecting to peer address:", peer_address, " preferred send date is ", preferred_send_date)
            # Binding socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.detect_host_local_ip(), UDP_PORT_NUMBER))

            # Sending hello immediately
            send_ready = select.select([], [sock], [], 1)
            if send_ready[1]:
                diffs = messages.compare_datetime(preferred_send_date)
                time.sleep(abs(diffs+self.DELTA))
                sent = sock.sendto("HELLO".encode(), peer_address)
                print("hello sent...")
                print("diff time was ", diffs)

            x = 0
            hello_state = 1
            device_preferred_udp_port = None
            
            while True:
                # Stop thread if it exceeds max tries
                if x > constants.MAX_TRIES_PEER:
                    print("max tries exceeded. quitting")
                    return

                # If connection is not established send a hello message to keep socket open
                if (not conn_est or (x % 10 == 0)): #and end_state is False:
                    send_ready = select.select([], [sock], [], 1)
                    if send_ready[1]:
                        sent = sock.sendto("HELLO".encode(), peer_address)
                        print("hello sent...")

                print("starting select..")
                ready = select.select([sock], [], [], 1)
                print("after select...")


                if ready[0]:
                    print("inside ready ... ")

                    try:
                        address = '0'
                        try:
                            data, address = sock.recvfrom(constants.MAX_UDP_RECEIVE_SIZE)
                            print("CAMERA GOT PEER MESSAGE...")
                            print("address is ", address,
                                " peer address is ", peer_address)
                        except Exception as err:
                            print("Exception in sock.recvfrom ", err)
                        
                        # If camera receives a packet from the same device address passed from the broker
                        if address == peer_address:
                            

                            # Connection is established
                            x = 1
                            conn_est = True
                                
                            # If the first byte of received packet is 1 the packet is encrypted
                            if data[0] == 1:
                                print("GOT ENCRYPTED COMMAND")
                                # Decrypt the packet using the camera's private key ignoring the first byte that says it's encrypted
                                dcr_data = security.decrypt_rsa(
                                    data[constants.ENCRYPTION_HEADER_SIZE:], priv_key)
                                transaction_id, message_type, seq, numseq, message_length, aes_key, aes_iv, payload = messages.parse_peer_message(
                                    dcr_data)
                                print("Got message ", transaction_id, message_type, 
                                        seq, numseq, message_length, aes_key, aes_iv, payload)
                                

                                print("handle the hello1,2,3 in this code block")
                                if hello_state == 1:
                                    print("hello state = 1", message_type)
                                    if message_type == 11: # hello1 received

                                        # Received Hello1 Sending Hello2
                                        device_preferred_udp_port = payload.decode("utf-8")
                                        messages.send_hello2(sock, peer_address, PREFERRED_UDP_PORT,0,aes_key,aes_iv,self.DELTA)
                                        hello_state = 2
                                        print("sent hello 2 and got device_preferred_udp_port ", device_preferred_udp_port)

                                elif hello_state==2:
                                    print("hello state = 2")
                                    if message_type == 13: # hello3 received
                                        messages.send_hello3(sock, peer_address,device_preferred_udp_port,0,aes_key,aes_iv,datetime.datetime.utcnow())
                                        hello_state = 3

                                        hello3_payload = str(payload.decode("utf-8")).split(',')
                                        
                                        print("got hello 3, switching to new thread")
                                        if int(hello3_payload[0]) == int(PREFERRED_UDP_PORT):

                                            new_thread_preferred_send_date = messages.str_to_datetime(hello3_payload[1])
                                            print("new_thread_preferred_send_date: ", new_thread_preferred_send_date)

                                            print("peer address was ", peer_address)
                                            peer_address = (peer_address[0], int(device_preferred_udp_port))
                                            print("peer address is now ", peer_address)
                                            sock.close()
                                            print("closed the socket")
                                            #self.udp_com_final(int(PREFERRED_UDP_PORT), peer_address, priv_key)
                                            break
                                        else: #Reset
                                            hello_state = 1
                                            



                            elif data.decode("utf-8") == "HELLO":
                                print("GOT HELLO MESSAGE")
                                # If got hello respond with hello
                                send_ready = select.select([], [sock], [], 1)
                                if send_ready[1]:
                                    sent = sock.sendto(
                                        "HELLO".encode(), peer_address)
                                continue
                        
                    except Exception as err:
                        print("Exception in select inner loop ", err)
                        print(sock.getsockname())

                print("Camera trying to communicate with peer...",
                      peer_address, " connection is ", conn_est)
                x += 1

            print("broke out of the while loop calling self.udp_com_final")
            self.udp_com_final(PREFERRED_UDP_PORT, peer_address, priv_key, new_thread_preferred_send_date)
            
        except Exception as err:
            print("Exception in inner loop", err)



    def handle_input(self,data,priv_key):
        try:
            if(data[0] == 1):   
                #dcr_data = security.decrypt_rsa(data[constants.ENCRYPTION_HEADER_SIZE:], priv_key)
                print("got data of length ", len(data))
                enckey,enciv,decpayload = messages.parse_peer_encrypted_message(priv_key, data)
                return decpayload
            else:
                return data

        except Exception as err:
            constants.CAMERA_THREAD_QUIT_SIGNAL = True
            print("Exception in self.handle_input", err)

    def handle_output(self,dcr_data,sock,peer_address,priv_key):
        try:
                       
            transaction_id, message_type, seq, numseq, message_length, aes_key, aes_iv, payload = messages.parse_peer_message(dcr_data)
            #try:
            #    print("payload is ", payload)
            #    print("got the output", payload.decode('utf-8'), transaction_id, message_type, seq, numseq, message_length)
            #except Exception as err:
            #    print("Exception in self.handle_output ", err)
                
            ret_msgs = []
            if message_type == 4:  # command message
                print("got a command message ")
                response_message_bytes = self.udp_com_thread_handle_data(
                    dcr_data)
                print("got response message bytes of size ", len(response_message_bytes))
                fragment_list = messages.udp_send_fragments(
                    response_message_bytes, constants.MAX_UDP_SEND_SIZE-constants.MESSAGE_HEADER_SIZE-constants.ENCRYPTION_HEADER_SIZE,
                    transaction_id, aes_key, aes_iv)
                print("got fragment list")
                # put the fragments into a dictionary with the datetime and list
                packet = [transaction_id, fragment_list]
                self.packet_list.append(packet)
                ret_msgs.append((peer_address,fragment_list[1]))

            # Else if received packet is of request type (msg_type = 5) handle request and send lost fragments
            elif message_type == 5:
                print(
                    "handle message type 5 here... Seq missing is " + payload.decode())
                missing_fragments_list = payload.decode().split(" ")

                # For every missing fragment from the list of lost sequences send it fragment to device
                fragments = []
                for sequence in missing_fragments_list[:-1]:
                    print(
                        "Requested Fragment of Sequence " + str(sequence) + " has been sent")
                    fragment = self.get_fragment(
                        transaction_id, int(sequence)-1)
                    fragments.append(fragment)
                ret_msgs.append((peer_address,fragments))
                #send_ready = select.select([], [sock], [], 1)
                #if send_ready[1]:
                #    sent = sock.sendto(
                #        fragment, peer_address)
                #sock.connect(peer_address)
            elif message_type == 11: # Hello1 is received
                pass
                #print("Got Hello1 ...")
                #send_ready = select.select([], [sock], [], 1)
                #if send_ready[1]:
                #    sent = sock.sendto("HELLO".encode(), peer_address)
                #    print("Sent Hello back")
            print("returning ret_msgs")
            return ret_msgs
        except Exception as err:
            constants.CAMERA_THREAD_QUIT_SIGNAL = True
            print("Exception in Queue Handler", err)

    def check_con(self,sock, UDP_CLIENT_PORT, PUB_KEY, peer_address):
        print("in check_con")
        conn_est = False
        x = 0

        while not conn_est and not constants.CLIENT_THREAD_QUIT_SIGNAL:
            
            # Stop thread if it exceeds max tries
            if x > constants.MAX_TRIES_PEER:
                print("max tries exceeded...quitting...")
                constants.CLIENT_THREAD_QUIT_SIGNAL = True
                return False, ""

            '''
            # If connection is not established send a hello message to keep socket open
            if (x % 5 == 0): #and end_state is False:
                send_ready = select.select([], [sock], [], 1)
                if send_ready[1]:
                    sent = sock.sendto("HELLO".encode(), peer_address)
                    print("hello sent...")
            '''

            print("starting select..")
            ready = select.select([sock], [], [],0.02)

            if ready[0]:
                print("inside ready ... ")
                try:
                    address = '0'
                    try:
                        data, address = sock.recvfrom(constants.MAX_UDP_RECEIVE_SIZE)
                        print("CAMERA GOT PEER MESSAGE...")
                        print("address is ", address,
                            " peer address is ", peer_address)
                    except Exception as err:
                        print("Exception in sock.recvfrom ", err)
                    
                    # If camera receives a packet from the same device address passed from the broker
                    if address == peer_address:
                        # Connection is established
                        x = 1
                        conn_est = True

                        # connection established
                        return True,data
                    
                except Exception as err:
                    constants.CAMERA_THREAD_QUIT_SIGNAL = True
                    print("Exception in select inner loop ", err)
                    print(sock.getsockname())
            else:
                messages.send_hello(sock,None,0,peer_address)

            print("Camera trying to communicate with peer...", peer_address, " connection is ", conn_est)
            x += 1

    # Threads initializer
    def final_com_threads(self,sock,UDP_CLIENT_PORT, priv_key, dev_addr, data):
        # Threads Shared Variables
        msg_out_queue = queue.Queue()
        msg_in_queue = queue.Queue()

        print("got data")

        # Starting self.receiver Thread
        print("Starting Receiving Thread")
        Thread(target=self.receiver, args=(sock,msg_out_queue, msg_in_queue,dev_addr)).start()
        print("Receiving Thread Started")

        # Starting Receive Handler Thread
        print("Starting Receive Handler Thread")
        Thread(target=self.receive_handler, args=(sock, msg_out_queue, msg_in_queue, priv_key, dev_addr)).start()
        print("Receive Handler Thread Started")


        # Starting Sending Thread
        print("Starting Sending Thread")
        Thread(target=self.sender, args=(sock, msg_out_queue, msg_in_queue, priv_key, dev_addr)).start()
        print("Sending Thread Started")


        # Starting Hello Thread
        print("Starting Con Thread")
        Thread(target=self.con_handler, args=(msg_out_queue, msg_in_queue,dev_addr)).start()
        print("Con Thread Started")

    # Receiving handler Thread - Receives messages and add them to queue
    def receiver(self,sock,msg_out_queue, msg_in_queue,dev_addr):
        print("Receive Thread has Started")

        x = 0
        
        try:
            while not constants.CLIENT_THREAD_QUIT_SIGNAL:

                #print("starting select..")
                ready = select.select([sock], [], [],1)
                # Stop thread if it exceeds max tries
                if x > constants.MAX_TRIES_PEER:
                    #print("self.receive_handler max tries exceeded...quitting...")
                    return

                if ready[0]:
                    try:
                        #print("starting receive..")
                        address = '0'
                        try:
                            data, address = sock.recvfrom(constants.MAX_UDP_RECEIVE_SIZE)
                            print("receiving GOT DATA from ... ", address, " with ", data[0])#, data)
                            print("dev_addr is ", dev_addr)
                        except Exception as err:
                            print("Exception in sock.recvfrom ", err)

                        # If device receives a packet from the same camera address passed from the broker
                        if address == dev_addr:
                            print(" the data is from the camera ")
                            # Connection is established
                            x = 0
                            conn_est = True
                            if data[0] != 72:   # If data is not a hello msg add it to queue
                                print("Going into the receive condition")
                                with self.RECEIVE_CONDITION:
                                    print("got non hello message")
                                    msg_in_queue.put(data)
                                    self.RECEIVE_CONDITION.notify_all()
                                    print("put data in the queue")

                            
                    except Exception as err:
                        constants.CLIENT_THREAD_QUIT_SIGNAL = True
                        print("Exception in select inner loop ", err)
                        print(sock.getsockname())
                else:
                    print("self.receiver no resp yet...")
                x += 1
        except Exception as err:
            constants.CLIENT_THREAD_QUIT_SIGNAL = True
            print("Exception in self.receiver thread occurred: ", err)

    # receive handler Thread - Decrypts messages from queue, process them and send requested packets
    def receive_handler(self,sock, msg_out_queue, msg_in_queue, priv_key, dev_addr):
        try:

            list_packets = []
            #cnt = 0
            _data = None
            msg = None
            #MAX_EMPTY_REPS = 7
        
            while not constants.CLIENT_THREAD_QUIT_SIGNAL  :
                #print("waiting to handle receive...")


                with self.RECEIVE_CONDITION:
                    while (msg_in_queue.empty()): 
                        self.RECEIVE_CONDITION.wait(1)
                        if constants.CLIENT_THREAD_QUIT_SIGNAL:
                            return
                            
                        #print("got notified data in queue...")

                
                #print("in queue size is ", msg_in_queue.qsize())
                if msg_in_queue.qsize() > 0:
                    constants.CLIENT_THREAD_SEND_PEER_MESSAGE = False
                    _data = msg_in_queue.get()         

                # if something is received
                if _data:
                    data = self.handle_input(_data,priv_key)
                    print("received data...handling it")
                    out_msgs = self.handle_output(data,sock,dev_addr,priv_key)
                    print("putting the data on the out queue of size ", len(out_msgs), " of type ", type(out_msgs))
                    with self.SEND_CONDITION:
                        msg_out_queue.put(out_msgs)
                        self.SEND_CONDITION.notify_all()
                        print("notified the out_queue")
                else:
                    continue


        except Exception as err:
            constants.CLIENT_THREAD_QUIT_SIGNAL = True
            print("Exception in self.receive_handler", err)

    # Receiving handler Thread - Receives messages and add them to queue
    def sender(self,sock,msg_out_queue, msg_in_queue,priv_key, dev_addr):
        print("self.sender Thread has Started")


        try:
            while not constants.CLIENT_THREAD_QUIT_SIGNAL:
                with self.SEND_CONDITION:
                   while msg_out_queue.empty():
                       #print("self.sender waiting for data .. ")
                       self.SEND_CONDITION.wait()
                
                #print("self.sender has data ... sending ")
                out_msgs = msg_out_queue.get()
                cnt = 0
                while cnt < len(out_msgs[0][1]):
                    send_ready = select.select([], [sock], [], 1)
                    if send_ready[1]:
                        print("type of out_msg is ", type(out_msgs))
                        print("size of out_msg is ", len(out_msgs))
                        print("seding peer address is ", out_msgs[0][0])
                        print("sending payload of type ", type(out_msgs[0][1][cnt]) , " length is ", len(out_msgs[0][1][cnt]))
                        #print("data to send is ", out_msgs[0][1][cnt])
                        sent = sock.sendto(out_msgs[0][1][cnt], out_msgs[0][0])
                        #[(peer_address,[msg1,msg2,...])]
                        cnt+=1
                        #time.sleep(0.005)
                    
                #if data[0] != 72:
                #    self.handle_output(data,sock,dev_addr,priv_key)
                #else:
                #    messages.send_hello(sock,None,0,dev_addr)

        except Exception as err:
            constants.CLIENT_THREAD_QUIT_SIGNAL = True
            print("Exception in self.sender thread occurred: ", err)

    # Connection handler Thread - Responsible for keeping connection alive
    def con_handler(self,msg_out_queue, msg_in_queue,peer_address):
        while not constants.CLIENT_THREAD_QUIT_SIGNAL :
            if msg_out_queue.empty():
                with self.SEND_CONDITION:
                    msg_out_queue.put([ (peer_address,[bytearray("HELLO".encode("utf-8"))] )  ]  )
                    self.SEND_CONDITION.notify_all()
            time.sleep(10)

    def udp_com_final(self,UDP_PORT_NUMBER, peer_address, priv_key, preferred_send_date):
        print("self.udp_com_final")
        #messages_queue = queue.Queue()
        try:


            # Binding socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.detect_host_local_ip(), UDP_PORT_NUMBER))

            # Sending hello immediately
            messages.send_hello(sock,preferred_send_date,self.DELTA,peer_address)
            
            # sock.connect(peer_address)  ##even with UDP connect forces it to only receive from this server address
            conn_est = False
            print("In self.udp_com_thread...starting comm on Final port:",
                  UDP_PORT_NUMBER, " connecting to peer address:", peer_address)

            conn_est, first_packet = self.check_con(sock, UDP_PORT_NUMBER, priv_key, peer_address)
            if(conn_est):
                # connection established, Start Rec,Send,Com Threads
                self.final_com_threads(sock,UDP_PORT_NUMBER, priv_key, peer_address, first_packet)
            else:
                # connection  failed
                constants.CLIENT_THREAD_QUIT_SIGNAL = True
                return
        except Exception as err:
            constants.CAMERA_THREAD_QUIT_SIGNAL = True
            print("Exception in inner loop", err)

    # Launch a thread for every device connected to the broker
    def launch_udp_com_threads(self,dict_msg, UDP_PORT_NUMBER, priv_key):
        # format { 'message' = '3', 'clients' : [ (ip,port,date), .. , ]
        for x in range(0, len(dict_msg['clients'])):
            print("Number of clients: " + str(len(dict_msg['clients'])))
            ##thread safe get new secure_udp_camera.UDP_PORT_NUMBER
            with self.UDP_SEND_LOCK:
                preferred_udp_port = self.generate_port()

            print("preferred send date is ", dict_msg['preferred_send_dates'])
            
            Thread(target=self.udp_com_thread, args=(UDP_PORT_NUMBER,
                   (dict_msg['clients'][x][0], dict_msg['clients'][x][1]), priv_key,
                                                messages.str_to_datetime(dict_msg['preferred_send_dates'][x]),
                                                preferred_udp_port,)).start()



    # Returns Local Ip
    def detect_host_local_ip(self):
        print("get the local ip and return it")
        return '192.168.20.65'
        #return '192.168.1.8'
        #return '192.168.20.70'
        #return '0.0.0.0'





    # Camera Main Code
    def start_udp_camera(self,PRIV_KEY, PUB_KEY, MASTER_PUB_KEY,  i):

        i = i % len(constants.BROKER_LIST)
        if secure_udp_camera.UDP_PORT_NUMBER is None:
            secure_udp_camera.UDP_PORT_NUMBER = random.randint(10000, 65000)
            print("secure_udp_camera.UDP_PORT_NUMBER is ", secure_udp_camera.UDP_PORT_NUMBER)

        secure_udp_camera.check_con.UDP_CAMERA_PORT = 0
        while True:
            secure_udp_camera.UDP_CAMERA_PORT = random.randint(10000, 65000)
            if secure_udp_camera.UDP_CAMERA_PORT != secure_udp_camera.UDP_PORT_NUMBER:
                break
        print("UDP CAMERA PORT is ", secure_udp_camera.UDP_CAMERA_PORT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # if not hasattr(socket, 'SO_REUSEPORT'):
        #    socket.SO_REUSEPORT = 15
        # else:
        #    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        camera_address = (self.detect_host_local_ip(), secure_udp_camera.UDP_PORT_NUMBER)
        print(camera_address)
        sock.bind(camera_address)


        server_address = self.get_broker(self.COUNTRY_CODE, i)

        # SEND SYNCH MESSAGE - Connect to broker
        session = self.generate_session()
        passcode = self.generate_passcode()
        key, iv = security.generate_aes_key()

        
        synch_msg = messages.generate_synch_message(
            session, passcode, self.SERIAL, secure_udp_camera.UDP_CAMERA_PORT, key, iv)
        print("Sending synch message of length ... ", len(synch_msg))
        messages.send_broker_message(
            self.COUNTRY_CODE, sock, MASTER_PUB_KEY, i+1, server_address, synch_msg, encrypt=True)
        last_synch_count = 0
        # END SYNCH MESSAGE

        secure_udp_camera.portsList.append(camera_address[1]) # Camera to broker
        secure_udp_camera.portsList.append(secure_udp_camera.UDP_CAMERA_PORT)   # Camera to Device
        secure_udp_camera.portsList.append(server_address[1]) # broker

        ping_resp = messages.get_broker_message(self.COUNTRY_CODE, sock, MASTER_PUB_KEY, key, iv, max_tries=3)
        print("ping_resp is ", ping_resp)
        ##GET NTP SYNCH
        self.DELTA = messages.broker_get_delta(MASTER_PUB_KEY, self.COUNTRY_CODE, sock, server_address, self.SERIAL, key,iv)
        print("DELTA is ", self.DELTA)

        

        no_resp = 0
        while True:
            try:
                ready = False

                ready = select.select([sock], [], [], 1)
                if ready[0]:
                    no_resp = 0
                    data, address = sock.recvfrom(constants.MAX_UDP_RECEIVE_SIZE)
                    enc_byte = data[0]
                    #print("enc_byte is ", enc_byte)
                    data = data[constants.ENCRYPTION_HEADER_SIZE:len(data)]
                    #print("data check sum is ", int(
                    #    data[0]) + int(data[len(data)-1]), type(data))
                    if enc_byte == 1:
                        print("entering enc byte", key, iv)
                        print("data is...", data)
                        try:
                            message_str = security.decrypt_aes(
                                data, key, iv).decode('utf-8')
                            message_str = json.loads(message_str)
                            for x in range(len(message_str["clients"])):
                                print("launching udp threads ....")
                                self.launch_udp_com_threads(
                                    message_str, secure_udp_camera.UDP_CAMERA_PORT, PRIV_KEY)

                            message = messages.generate_remove_client_message(
                                session, passcode, self.SERIAL)
                            messages.send_broker_message(
                                self.COUNTRY_CODE, sock, MASTER_PUB_KEY, 0, server_address, message)

                        except Exception as err:
                            print(err)

                            # synch_msg = messages.generate_synch_message(session, passcode, SERIAL, key, iv)
                            # messages.send_broker_message(self.countRY_CODE, sock, MASTER_PUB_KEY, i+1, server_address, synch_msg, encrypt=True)

                    else:
                        pass
                        #print(
                        #    "Broker responds with no clients, or message would be encrypted...ignoring it")
                        #print(data)
                        # message_str = data.decode('utf-8')
                        # result = messages.verify_ping_response(session,passcode,message_str)
                        # if result == True: ##what to do if the message is false ??
                        #    synch_msg = messages.generate_synch_message(session, passcode, SERIAL)
                        #    messages.send_broker_message(self.countRY_CODE, sock, MASTER_PUB_KEY, i+1, server_address, message)

                else:
                    # how to handle this ??
                    #print("No response from server yet...")
                    no_resp += 1
                    message = messages.generate_ping_message(session, passcode)
                    messages.send_broker_message(
                        self.COUNTRY_CODE, sock, MASTER_PUB_KEY, 0, server_address, message, encrypt=False)
                    

                if no_resp >= 30:
                    sock.close()
                    self.start_udp_camera(PRIV_KEY, PUB_KEY, MASTER_PUB_KEY, i+1)

                last_synch_count += 1
                if last_synch_count > 300:
                    last_synch_count = 0
                    session = self.generate_session()
                    passcode = self.generate_passcode()
                    synch_msg = messages.generate_synch_message(
                        session, passcode, self.SERIAL, secure_udp_camera.UDP_CAMERA_PORT, key, iv)
                    messages.send_broker_message(
                        self.COUNTRY_CODE, sock, MASTER_PUB_KEY, i+1, server_address, message, encrypt=True)
                    self.DELTA = messages.broker_get_delta(MASTER_PUB_KEY, self.COUNTRY_CODE, sock, server_address, self.SERIAL, key,iv)

            except Exception as err:
                print("Exception in outer loop " + str(err))
        



#security.generate_keys('test',4096)
#security.generate_keys('master',4096)
PRIV_KEY, PUB_KEY = security.load_keys('cam')
test, MASTER_PUB_KEY = security.load_keys('master')
test = None
dev = secure_udp_camera()
dev.start_udp_camera(PRIV_KEY, PUB_KEY, MASTER_PUB_KEY, 0)
