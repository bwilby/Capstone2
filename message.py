from datetime import datetime, date, timedelta
import datetime
import hashlib
import json
import random
import base64
import security
import constants
import select
import time
## MESSAGE TYPES##

def get_byte(int_val, num_bytes):
    # you must be aware how many bytes you need
    byte_val = int_val.to_bytes(num_bytes, byteorder='big')
    return bytearray(byte_val)


def generate_encrypt_header(encr, seq, numseq):
    return  bytearray(get_byte(encr, 1)) + bytearray(get_byte(seq, 2)) + bytearray(get_byte(numseq, 2)) 


head = generate_encrypt_header(1, 29000, 64000)
for x in range(0,len(head)):
    print(int(head[x]))

def datetime_to_str(dt):
    str_dt = dt.strftime('%m/%d/%Y %H:%M:%S.%f')
    return str_dt


def str_to_datetime(str_dt):
    dt = datetime.datetime.strptime(str_dt, '%m/%d/%Y %H:%M:%S.%f')
    return dt



def compare_time(str_dt):
    dt = str_to_datetime(str_dt)
    dtnow = datetime.datetime.utcnow()
    diff = dtnow-dt
    diff = diff.total_seconds()
    return diff

def compare_datetime(dt):
    dtnow = datetime.datetime.utcnow()
    diff = dtnow-dt
    diff = diff.total_seconds()
    return diff

def calc_client_time(cam_t, cam_delay, client_delay, client_num):
    try:
        dtnow = datetime.datetime.utcnow()
        print(dtnow)
        seconds = dtnow.second % 10
        diff = int(2*cam_t - (seconds % cam_t) + 2 * max(cam_delay,client_delay) + client_num) + 1
        # datetime(year, month, day, hour, minute, second, microsecond)
        b = datetime.datetime(dtnow.year, dtnow.month, dtnow.day, dtnow.hour, dtnow.minute, dtnow.second , 0) + datetime.timedelta(seconds=diff)
        return b
    except Exception as err:
        print("exception in calc time ", err)

print(calc_client_time(2, 0.6, 0.8, 1))
def convert_message_str_to_dict(message):
    out_dict = json.loads(message)
    if 'date' in out_dict.keys():
        out_dict['date'] = str_to_datetime(out_dict['date'])

    return out_dict


def generate_ntp_message(serial, key, iv):
    print("ntp message") ##send encrypted message to ask for a passcode from broker
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    key = base64.b64encode(key).decode('utf-8')
    iv = base64.b64encode(iv).decode('utf-8')
    
    message = {'message': '0', 
               'datetime': dt_utcnow, 'serial': serial ,'key': key, 'iv': iv, }
    msg_str = json.dumps(message)
    print(msg_str)
    return msg_str


def generate_ntp_message_response(passcode):
    print("ntp message resp") ##broker responds with a passcode
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())

    message = {'message': '0', 
               'datetime': dt_utcnow, 'passcode': passcode }
    msg_str = json.dumps(message)
    print(msg_str)
    return msg_str



def generate_ntp_ping_message(passcode):  # sent by camera to broker
    
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    msg = "ntp " + passcode + "\n" + str(dt_utcnow) + "\n"
    #print("ntp ping message ", msg)
    return msg


def generate_ntp_ping_request(passcode):  # sent by broker to camera
    
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    msg = "ntp1 " + passcode + "\n" + str(dt_utcnow) + "\n"
    #print("ntp ping message ", msg)
    return msg

def parse_check_ntp_ping(msg, dict_check):
    try:
        print("msg start is ", msg[0:3])
        if msg[0:3] == 'ntp':
            print(" ntp message ping ")
            tokens = msg[3:].split('\n')
            passcode = tokens[0].strip()
            dt_str = tokens[1].strip()
            print(" tokens are ", tokens)
            if passcode in dict_check.keys():
                print("token is in the dictionary")
                del dict_check[passcode]
                return generate_ntp_ping_message_response(dt_str)
            print("token not in dictionary")
            
        return None
    except Exception as err:
        print(" exception in parse_check_ntp_ping", err)
        return None

def generate_ntp_ping_message_response(str_dt):  # sent by camera to broker
    #print("ntp ping message response")
    diff = compare_time(str_dt)
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    msg = "ntp2 " + str(diff) + "\n" + str_dt + "\n" + str(dt_utcnow) + "\n"
    print(" delta message is..................", msg)
    return msg

def parse_ntp_ping_message_response(msg):
    tokens = msg[4:].split("\n")
    diff = float(tokens[0])
    trip = compare_time(tokens[1])/2
    delta = diff - trip 
    return delta

# from camera to broker -> pass key,iv for return secure communication
def generate_synch_message(session, passcode, serial, port, key, iv, t=2):
    print("synch message")
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    trno = random.randint(10000000, 100000000)
    key = base64.b64encode(key).decode('utf-8')
    iv = base64.b64encode(iv).decode('utf-8')
    message = {'message': '1', 'trn': trno, 'session': session, 'passcode': passcode,
               'datetime': dt_utcnow, 'serial': serial, 'camera_port': port, 'key': key, 'iv': iv, 't':t}
    msg_str = json.dumps(message)
    print(msg_str)
    return msg_str


# from camera to broker, return communication is hashed
def generate_remove_client_message(session, passcode, serial):
    print("remove client message")
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    trno = random.randint(10000000, 100000000)
    message = {'message': '2', 'trn': trno, 'session': session,
               'passcode': passcode, 'datetime': dt_utcnow, 'serial': serial}
    msg_str = json.dumps(message)
    print(msg_str)
    return msg_str


# from client to broker, send key,iv to get a response
def generate_add_client_message(serial, session, passcode, port, key, iv, local_ip):
    print("add client message")
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    trno = random.randint(10000000, 100000000)
    key = base64.b64encode(key).decode('utf-8')
    iv = base64.b64encode(iv).decode('utf-8')
    message = {'message': '3', 'trn': trno, 'serial': serial, 'session': session,
               'passcode': passcode, 'datetime': dt_utcnow, 'client_port': port, 'key': key, 'iv': iv,
               'local_ip': local_ip}
    msg_str = json.dumps(message)
    print(msg_str)
    return msg_str


# broker sends back this communication encrypted with key,iv sent earlier
def generate_synch_message_response(serial, session, passcode, clients, client_dict):
    print("synch message response")
    preferred_dts = []
    for x in range(0,len(clients)):
        preferred_dts.append(datetime_to_str(client_dict[clients[x]][1]))
    
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    trno = random.randint(10000000, 100000000)
    message = {'message': '1', 'trn': trno, 'serial': serial, 'session': session,
               'passcode': passcode, 'clients': clients, 'datetime': dt_utcnow,
               'preferred_send_dates': preferred_dts}
    msg_str = json.dumps(message)
    print(msg_str)
    return msg_str


# broker sends back this communication encrypted with key,iv sent earlier
def generate_client_message_response(serial, session, passcode, server_addr, send_date):
    print("client message response")
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    trno = random.randint(10000000, 100000000)
    print(" The transaction number is ", trno)
    message = {'message': '3', 'trn': trno, 'serial': serial, 'session': session,
               'passcode': passcode, 'server_addr': server_addr, 'datetime': dt_utcnow,
               'preferred_send_date': datetime_to_str(send_date)}
    msg_str = json.dumps(message)
    print(msg_str)
    return msg_str


def generate_hello_message():
    return "HELLO"

# Generate Hello1 header
def generate_hello1_message(port):
    transaction_id = random.randint(10000000, 100000000)
    message_type = 11
    payload_bytes = bytearray(str(port).encode('utf-8'))
    header = format_peer_message_header(
            transaction_id, message_type, len(payload_bytes), 1, 1)
    return header


# Generate Hello2 header
def generate_hello2_message(port):
    transaction_id = random.randint(10000000, 100000000)
    message_type = 12
    payload_bytes = bytearray(str(port).encode('utf-8'))
    header = format_peer_message_header(
            transaction_id, message_type, len(payload_bytes), 1, 1)
    return header

# Generate Hello3 header
def generate_hello3_message(port):
    transaction_id = random.randint(10000000, 100000000)
    message_type = 13
    payload_bytes = bytearray(str(port).encode('utf-8'))
    header = format_peer_message_header(
            transaction_id, message_type, len(payload_bytes), 1, 1)
    return header

def generate_ping_message(session, passcode, salt=None):  # sent by camera to broker
    print("ping message")
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    if salt == None:
        salt = str(dt_utcnow) + "\n"
    result = hashlib.sha256(base64.b64encode(
        (salt+session).encode())).hexdigest()
    return salt + result


# broker sends back this communication encrypted with key,iv sent earlier
def generate_ping_response(session, passcode, serial, have_clients, client_list, client_dict, key, iv, salt=None):
    print("ping message")
    dt_utcnow = datetime_to_str(datetime.datetime.utcnow())
    if len(client_list) == 0:
        if salt == None:
            salt = dt_utcnow + "\n"
        result = hashlib.sha256(base64.b64encode(
            (salt+session+str(have_clients)).encode())).hexdigest()
        return (salt + result).encode('utf-8')
    else:
        print("encrypting with aes")
        return security.encrypt_aes(generate_synch_message_response(serial, session, passcode, client_list, client_dict).encode('utf-8'), key, iv)


def verify_ping_response(session, passcode, message):
    salt_index = message.find("\n")
    if salt_index == -1:
        return None
    salt = message[0:salt_index+1]
    resp1 = generate_ping_response(session, passcode, True, salt=salt)
    resp2 = generate_ping_response(session, passcode, False, salt=salt)
    if resp1 == message:
        return True
    elif resp2 == message:
        return False
    else:
        return None


def generate_client_response(session, passcode, serial, camera_address, key, iv, salt=None):
    print("generate_client_response")
    message = generate_client_message_response(
        serial, session, passcode, camera_address)
    print("message is ", message)
    return security.encrypt_aes(message.encode('utf-8'), key, iv)

## MESSAGE TYPES##


## SEND MESSAGES##

def send_broker_message(country_code, sock, MASTER_PUB_KEY, i, server_address, message, encrypt=True):
    # if i >= constants.MAX_TRIES_BROKER:
    #    return None

    try:
        if encrypt:
            message_bytes = security.encrypt_rsa(
                message.encode('utf-8'), MASTER_PUB_KEY)
        else:
            message_bytes = message.encode('utf-8')
        #print("Sending message ... Encrypted = ",
        #      encrypt, " of size ", len(message_bytes))
        # sent a synch message now wait for response
        send_ready = select.select([], [sock], [], 1)
        if send_ready[1]:
            sent = sock.sendto(message_bytes, server_address)
            sock.connect(server_address)
    except Exception as err:
        print("exception in send broker message " + str(err))


def get_broker_message(country_code, sock, MASTER_PUB_KEY, key, iv, max_tries=3):
    i = 0
    while True:
        try:
            ready = False

            ready = select.select([sock], [], [], 1)
            if ready[0]:
                no_resp = 0
                data, address = sock.recvfrom(constants.MAX_UDP_RECEIVE_SIZE)
                enc_byte = data[0]
                #print("enc_byte is ", enc_byte)
                data = data[constants.ENCRYPTION_HEADER_SIZE:]
                if enc_byte == 1:

                    try:
                        message_str = security.decrypt_aes(
                            data, key, iv).decode('utf-8')

                        return message_str
                        
                    except Exception as err1:
                        print("exception in get broker message", err1)
                        return ""
                else:
                    data = data.decode('utf-8')
                    return data
            i+=1
            if i >= max_tries:
                return ""
        except Exception as err:
            print("exception in get_broker_message ", err)
            return ""

def broker_get_delta(MASTER_PUB_KEY, COUNTRY_CODE, sock, broker_address, serial, key,iv):
    try:
        tries = 0
        passcode = ''
        msg = ''
        while True:
            msg = generate_ntp_message(serial, key, iv)
            print("ntp message is ", msg)
            send_broker_message(COUNTRY_CODE, sock, MASTER_PUB_KEY, 1, broker_address, msg, encrypt=True)

            while True:
                msg = get_broker_message(COUNTRY_CODE, sock, MASTER_PUB_KEY, key, iv, max_tries=3)
                print("got ntp reply with passcode ", msg)
                if msg[0:4] == "ntp1":
                    break;
                tries += 1
                if tries > 3:
                    return 0
            
        
            tries = 0
            #print(" broker message is ", msg)
            passcode = msg.split()[1].strip()
            print(" Got the passcode ", passcode)
            ping_msg = generate_ntp_ping_message(passcode)
            print("sending ping_msg ", ping_msg)

            
            while True:
                send_broker_message(
                COUNTRY_CODE, sock, MASTER_PUB_KEY, 1, broker_address, ping_msg, encrypt=False)

                ping_msg_resp = get_broker_message(COUNTRY_CODE, sock, MASTER_PUB_KEY, key, iv, max_tries=3)
                print("got ping_msg_resp ", ping_msg_resp )
                
                if ping_msg_resp[0:4] == "ntp2":
                    break
                ping_msg_resp = get_broker_message(COUNTRY_CODE, sock, MASTER_PUB_KEY, key, iv, max_tries=3)
                tries += 1
                if tries > 3:
                    return 0
            print("got ping message response ", ping_msg_resp)
            delta = parse_ntp_ping_message_response(ping_msg_resp)
            print("delta ", delta )
            return delta
            

    except Exception as err1:
        print(err1)
        return 0




def get_int(byte_val):
    int_val = int.from_bytes(byte_val, byteorder='big')
    return int_val


def format_peer_message_header(transaction_id, message_type, message_len, curr_seq, num_seq):
    # transaction_ID must be less that 4 billion
    print("Transaction Id is ", transaction_id)
    message_header = bytearray(get_byte(transaction_id, 4)) + get_byte(
        32, 1) + get_byte(message_type, 1)  # transaction_id + space + message_type
    # space + seq + "/" + num_seq + space + payload_len
    message_header += get_byte(32, 1) + get_byte(curr_seq, 2) + get_byte(
        47, 1) + get_byte(num_seq, 2) + get_byte(32, 1) + get_byte(message_len, 2)
    # "/n"
    message_header += get_byte(15, 1)
    return message_header

# Used to parse fragments i.e messages received by the device from the camera
def parse_received_fragment(decrypted_message_bytes):
    transaction_id = get_int(decrypted_message_bytes[0:4])
    message_type = get_int(decrypted_message_bytes[5:6])
    seq = get_int(decrypted_message_bytes[7:9])
    numseq = get_int(decrypted_message_bytes[10:12])  # 10:11, 11:13, 13:14
    message_len = get_int(decrypted_message_bytes[13:15])
    payload = decrypted_message_bytes[16:]
    return transaction_id, message_type, seq, numseq, message_len, payload

# Used to parse peer message which include AES key and iv i.e messages received by the camera from the device
def parse_peer_message(decrypted_message_bytes):
    transaction_id = get_int(decrypted_message_bytes[0:4])
    message_type = get_int(decrypted_message_bytes[5:6])
    seq = get_int(decrypted_message_bytes[7:9])
    numseq = get_int(decrypted_message_bytes[10:12])  # 10:11, 11:13, 13:14
    message_len = get_int(decrypted_message_bytes[13:15])
    print("message_type, seq, numseq, message_len", message_type, seq, numseq, message_len)
    # \n
    aes_key = bytes(decrypted_message_bytes[16:32])
    aes_iv = bytes(decrypted_message_bytes[32:48])
    print("aes_key, aes_iv ", aes_key, aes_iv)
    # \n
    payload = decrypted_message_bytes[49:]
    print("decrypted payload ", payload)
    print("transaction_id, message_type, seq, numseq, message_len",transaction_id, message_type, seq, numseq, message_len)
    return transaction_id, message_type, seq, numseq, message_len, aes_key, aes_iv, payload
# by default it is a command message, #5 means resend message
def send_peer_message(sock, PUB_KEY, server_address, message, aes_key, aes_iv, message_type=4):
    # if i >= constants.MAX_TRIES_BROKER:
    #    return None
    print("sending peer message...")
    try:
        '''
        transaction_id = random.randint(1000000, 9000000)
        payload_bytes = message #bytearray(message.encode('utf-8'))
        # KEY + IV/n
        AES_bytes = bytearray(aes_key) + bytearray(aes_iv) + get_byte(15, 1)
        print("aes_key, aes_iv", aes_key, aes_iv)
        message_header = format_peer_message_header(
            transaction_id, message_type, len(payload_bytes), 1, 1)
        #print("message_header size is ", len(message_header))
        #message_bytes = security.encrypt_rsa(
        #    message_header+AES_bytes+payload_bytes, PUB_KEY)
        print("rsa header before encryption is ", message_header+AES_bytes)
        enc_bytes = bytearray(security.encrypt_rsa(
            message_header+AES_bytes, PUB_KEY))
        #print("rsa header is ", enc_bytes, " of size ", len(enc_bytes))
        print("unencrypted bytes", payload_bytes)
        pay_bytes = bytearray(security.encrypt_aes(payload_bytes, aes_key, aes_iv))
        message_bytes = enc_bytes + pay_bytes
        print("encrypted bytes", pay_bytes)
        
        if message_bytes is None:
            print("failed to message ", payload_bytes)
            generate_encrypt_header(1, 1, 1)

        #print("message before header is ", message_bytes)
        final = generate_encrypt_header(1, 1, 1)  + bytearray(message_bytes)
        '''
        #final = generate_command_message(PUB_KEY, message, aes_key, aes_iv, message_type=message_type)
        # sent a synch message now wait for response
        send_ready = select.select([], [sock], [], 1)
        if send_ready[1]:
            sent = sock.sendto(message, server_address)
        #sock.connect(server_address)
    except Exception as err:
        print("exception in send_peer_message", err)




# by default it is a command message, #5 means resend message
def generate_command_message(PUB_KEY, message, aes_key, aes_iv, transaction_id=None, message_type=4):
    # if i >= constants.MAX_TRIES_BROKER:
    #    return None
    #print("sending peer message...of size", len(message))
    try:
        #print("unencrypted command message is ", bytearray(message))
        #print("aes_key is ", aes_key)
        #print("aes_iv is ", aes_iv)
        if transaction_id is None:
            transaction_id = random.randint(1000000, 9000000)
        payload_bytes = message #bytearray(message.encode('utf-8'))
        # KEY + IV/n
        AES_bytes = bytearray(aes_key) + bytearray(aes_iv) + get_byte(15, 1)
        message_header = format_peer_message_header(
            transaction_id, message_type, len(payload_bytes), 1, 1)
        #print("message_header size is ", len(message_header))
        #message_bytes = security.encrypt_rsa(
        #    message_header+AES_bytes+payload_bytes, PUB_KEY)
        #print("rsa header before encryption is ", message_header+AES_bytes)
        enc_bytes = bytearray(security.encrypt_rsa(
            message_header+AES_bytes, PUB_KEY))
        #print("rsa header after encryption is ", enc_bytes)
        #print("rsa header is ", enc_bytes, " of size ", len(enc_bytes))
        pay_bytes = bytearray(security.encrypt_aes(payload_bytes, aes_key, aes_iv))
        message_bytes = enc_bytes + pay_bytes
        #print("AES encrypted payload is ", pay_bytes)
        #try:
        #    print("trying to recover the payload")
        #    tb = security.decrypt_aes(pay_bytes, aes_key, aes_iv)
        #    print("decrypted bytes are ", tb)
        #    cmsg = tb.decode('utf-8')
        #    print("the message was ", cmsg)

        #except Exception as err:
        #    print("err in test decoding command message ", err)
        
        if message_bytes is None:
            print("failed to message ", payload_bytes)
            generate_encrypt_header(1, 1, 1)

        #print("message before header is ", message_bytes)
        final = generate_encrypt_header(1, 1, 1)  + bytearray(message_bytes)
        #print("total message is ", final)
        return final
    except Exception as err:
        print("exception in generate_command_message", err)
'''
def parse_peer_encrypted_message(PRIV_KEY, message):
    headsize = constants.MESSAGE_HEADER_SIZE  + constants.ENCRYPTION_KEY_SIZE
    encpayload = message[headsize:]
    header_bytes = security.decrypt_rsa(message[0:headsize],PRIV_KEY)
    print("got decrypted rsa header bytes")
    key = message[constants.MESSAGE_HEADER_SIZE:constants.MESSAGE_HEADER_SIZE+16]
    iv = message[constants.MESSAGE_HEADER_SIZE+16:constants.MESSAGE_HEADER_SIZE+32]
    decpayload = security.decrypt_aes(encpayload, key, iv)
    return key,iv,decpayload
'''
def parse_peer_encrypted_message(PRIV_KEY, message):
    #print("total message is ", message)
    #print("got message, type is ", type(message))
    #message = message[constants.ENCRYPTION_HEADER_SIZE:]
    #print("got message size is ", len(message))
    message = message[constants.ENCRYPTION_HEADER_SIZE:]
    #print("message after header removal is ", message)
    headsize = constants.RSA_KEY_SIZE_IN_BYTES #constants.MESSAGE_HEADER_SIZE  + constants.ENCRYPTION_KEY_SIZE
    encpayload = message[headsize:]
    #print("rsa header is ", message[0:headsize])
    header_bytes = security.decrypt_rsa(message[0:headsize],PRIV_KEY)
    #print("decrypted the header_bytes size is ", len(header_bytes))
    #print("got decrypted rsa header bytes ", header_bytes)
    key = header_bytes[constants.MESSAGE_HEADER_SIZE:constants.MESSAGE_HEADER_SIZE+16]
    iv = header_bytes[constants.MESSAGE_HEADER_SIZE+16:constants.MESSAGE_HEADER_SIZE+32]
    #print("AES encrypted payload is ", encpayload)
    #print("got aes_key, aes_iv ", key, iv)
    decpayload = bytearray(security.decrypt_aes(encpayload, key, iv))
    #print("decpayload is ", decpayload)
    #try:
    #    msg_str = decpayload.decode('utf-8')
    #    print("messge is ", msg_str)
    #except Exception as err:
    #    print("Exception in parse_peer_encrypted_message ", err)
    decpayload = bytearray(header_bytes)+decpayload
    #print("decpayload is ", decpayload)
    return key,iv,decpayload

# add message_id as input  4 is for command  #3970643 4 1/1 32/nHEELLLLLLLOOOOOTHIS IS THE RESULT  #3970643 5 1/1 32/n1 2 4 5 7 8
# return datetime, fragment list
# Used in camera to send packets to device
#def udp_send_fragments(message_bytes, fragment_size, sock, peer_address, transaction_id, aes_key, aes_iv, message_type=4):
def udp_send_fragments(message_bytes, fragment_size, transaction_id, aes_key, aes_iv, message_type=4):

    message_bytes = security.encrypt_aes(message_bytes, aes_key, aes_iv)
    #print("send fragment function still has to be worked out here ... ")
    total_sent = 0
    last_sent = 0
    seq = 1
    print("fragment size is ", fragment_size, type(fragment_size))
    print("message_bytes size is ", len(
        message_bytes), type(len(message_bytes)))
    # 65507 or higher results in error
    # Number of Packets
    num_seq = int(len(message_bytes) / fragment_size)
    print("num_seq is ", num_seq, type(num_seq))
    if len(message_bytes) % fragment_size != 0:
        num_seq += 1

    fragment_list = []
    print("Num seq is ", num_seq)

    # iterate through all fragments encrypt them using AES and send them
    while seq <= num_seq:  # total_sent < len(message_bytes):
        print("in send loop...", seq, " of ", num_seq)
        send_bytes = None
        send_length = 0
        if fragment_size > len(message_bytes) - (last_sent + 1):
            send_length = len(message_bytes) - (last_sent + 1)
            send_bytes = message_bytes[last_sent:]
            print("Length of last send is ", len(send_bytes))

        else:
            send_length = fragment_size
            send_bytes = message_bytes[last_sent:last_sent+fragment_size]

        # send_bytes = (str(message_id) + " " + str(seq) + "/" + str(num_seq) + " " + str(send_length) + "/n").encode() + send_bytes
        header = format_peer_message_header(
            transaction_id, message_type, send_length, seq, num_seq)
        send_bytes = bytearray(header) + bytearray(send_bytes)
        #print("udp message sent was", send_bytes)  # .decode('utf-8'))
        encrypted_bytes = generate_encrypt_header(1, seq, num_seq)+ bytearray(send_bytes)#bytearray(security.encrypt_aes(send_bytes, aes_key, aes_iv))
        fragment_list.append(encrypted_bytes)
        #send_ready = select.select([], [sock], [], 1)
        #if send_ready[1]:
        #    sent = sock.sendto(encrypted_bytes, peer_address)
        seq += 1
        total_sent += send_length
        last_sent += send_length
    return [datetime_to_str(datetime.datetime.utcnow()), fragment_list]


'''
def fragment_parse(data):
    try:
        
        print("parsing data fragment...")
        #32 = space  47 = /     15 = /n
        tokens = []
        last_token = 0
        #3970643 1/1 32/nHEELLLLLLLOOOOOTHIS IS THE RESULT
        for x in range(0,len(data)):
            if data[x] == 32 or data[x] == 47:
                tokens.append(data[last_token:x])
                last_token=x+1
            if data[x] == 15:
                last_token=x+1
                break;


        print("message_id", tokens[0], "seq", tokens[1], "num_seq",  tokens[2], "send_length", tokens[3])
        return tokens[0], int(tokens[1]), int(tokens[2]), int(tokens[3]), data[last_token:len(data)-1]
        
    except Exception as err:
        print("Exception in fragment_parse..", err)
        return False,False,False,False,False
'''


# return msg  *** which is the the fully assembled packet
# Used in device to assemble and request packets from camera
'''
def udp_assemble_fragments(sock, cam_addr, msg_queue, data, aes_key, aes_iv, cam_pub_key):
    print("assembling udp fragments...")
    # transaction_id, message_type, seq, numseq, payload
    message_id, message_type, seq, num_seq, send_length, data = parse_received_fragment(
        data)
    # message_id, seq, num_seq, send_length, data = fragment_parse(data)

    total_packets = num_seq
    packet_list = [[]]*num_seq
    packet_list[seq-1] = data
    msg_id = message_id
    rec_int = 1

    MAX_TRIES = num_seq + 3
    curr_try = 1
    have_all = False

    # There is only one fragment
    if rec_int == total_packets:
        have_all = True


    # Attempt to receive all fragments, decrypt and assemble them
    while have_all == False:
        if not msg_queue.empty():
            data = msg_queue.get()
            print("received...", str(data)[-10:], " from ", cam_addr)

            # If data is encrypted or decrypted
            if data[0] == 1 or data[0] == 2:
                dcr_data = data[1:]
                if data[0] == 1:
                    dcr_data = security.decrypt_aes(data[1:], aes_key, aes_iv)
                message_id, message_type, seq, num_seq, send_length, data = parse_received_fragment(
                    dcr_data)

                # Induced Lost Fragments for sequences of 2 and 3 ------------------ Must be commented out after debugging
                # if seq == 2 or seq == 3:
                #     break

                # If the fragment is from the same packet
                if message_id == msg_id and len(packet_list[seq-1]) == 0:
                    packet_list[seq-1] = data
                    rec_int += 1
                # Else add to the end of queue
                else:
                    payload_bytes = bytearray(b'\x01') + bytearray(dcr_data)
                    msg_queue.put(payload_bytes)
            # Else If the data is not encrypted or decrypted
            else:
                if data.decode("utf-8") == "HELLO":
                    print("It is a hello message..")
                    send_hello1(sock, cam_addr, cam_addr[1],cam_pub_key,aes_key,aes_iv)
                else:
                    print("shouldn't be here X Got the data ", str(data)[-10:])
                    
            if rec_int == num_seq:
                have_all = True
                break
            time.sleep(0.1)
        else:
            if curr_try > MAX_TRIES:
                break

        curr_try += 1

    # If we have not received all fragments send a Lost Fragments Request to the Camera
    if have_all == False:
        message = ""
        # Construct a message of all sequences of lost fragments
        for x in range(0, len(packet_list)):
            if not packet_list[x]:
                message += str(x+1) + " "
                pass
            else:
                pass

        send_request_message(sock,cam_addr,msg_id,message, aes_key, aes_iv, cam_pub_key)

    # Reassemble Lost Fragments
    curr_try = 1
    while have_all == False:

        if not msg_queue.empty():
            data = msg_queue.get()
            print("received...", str(data)[-10:], " from ", cam_addr)
            if data.decode[0] == 72:
                send_hello1(sock, cam_addr, cam_addr[1],cam_pub_key,aes_key,aes_iv)
                continue

            # If data is encrypted or decrypted
            if data[0] == 1 or data[0] == 2:
                dcr_data = data[1:]
                if data[0] == 1:
                    dcr_data = security.decrypt_aes(data[1:], aes_key, aes_iv)
                message_id, message_type, seq, num_seq, send_length, data = parse_received_fragment(
                    dcr_data)
                
                if message_id == msg_id and len(packet_list[seq-1]) == 0:
                    print("Received Lost Packet " +
                          str(data)[-10:], " from ", cam_addr)
                    packet_list[seq-1] = data
                    rec_int += 1
                    curr_try = 0
                else:
                    payload_bytes = bytearray(b'\x01') + bytearray(dcr_data)
                    msg_queue.put(payload_bytes)
                    
                curr_try += 1
            else:
                curr_try += 1

        if rec_int == num_seq:
            have_all = True
            break
        if curr_try > MAX_TRIES:
            break

    msg = []
    if have_all:
        for x in range(0, len(packet_list)):
            msg.append(packet_list[x])

    print("Got message")
    return msg
'''

def udp_assemble_fragments(sock, cam_addr, msg_list, data, aes_key, aes_iv, cam_pub_key):
    print("assembling fragments len is ", len(msg_list.keys()))
    is_init = False
    have_all = False
    packet_list = None
    for key in msg_list.keys():
        data_ = msg_list[key]
        #print("assembling fragments data[0] is ", data_[0])
        if data_[0] == 1 or data_[0] == 2:
            dcr_data = data_[constants.ENCRYPTION_HEADER_SIZE:]
            if data_[0] == 1:
                #dcr_data = security.decrypt_aes(data_[constants.ENCRYPTION_HEADER_SIZE:], aes_key, aes_iv)
                #message_id, message_type, seq, num_seq, send_length, data = parse_received_fragment(dcr_data)
                message_id, message_type, seq, num_seq, send_length, data = parse_received_fragment(data_[constants.ENCRYPTION_HEADER_SIZE:])
                #print("type of data is ", type(data))
                #print("received data", message_id, message_type, seq, num_seq, send_length)
                if not is_init:
                    total_packets = num_seq
                    packet_list = [[]]*(num_seq)
                    packet_list[seq-1] = data
                    msg_id = message_id
                    print("Got response with transaction id ", msg_id, seq, num_seq)
                    rec_int = 1
                    is_init = True

            
                if message_id == msg_id and len(packet_list[seq-1]) == 0:
                    packet_list[seq-1] = data
                    rec_int += 1

                if rec_int == total_packets:
                    have_all = True
            else:
                print("data doesn't have correct start byte and isn't encrypted ")

        else:
            print("the data is not encrypted, shouldn't be here??? ", data_)

    print("done loop..........")
    if have_all == False:
        print("Don't have all packets")
        message = ""
        # Construct a message of all sequences of lost fragments
        for x in range(0, len(packet_list)):
            if not packet_list[x]:
                message += str(x+1) + " "
                print("message to resend is ", message)
                pass
            else:
                pass

        resend_msg = send_request_message(sock,cam_addr,msg_id,message, aes_key, aes_iv, cam_pub_key)
        return None,resend_msg

    else:
        print("have all ", type(packet_list))
        #msg = bytearray()
        #for x in range(0, len(packet_list)):
        #    print(type(packet_list[x]), x)#msg.append(packet_list[x])

        
        #msg = b"".join(bytes_obj for sublist in packet_list for bytes_obj in sublist)
        msg = bytes().join(packet_list)
        print("decrypting..", type(msg))
        msg = security.decrypt_aes(msg, aes_key, aes_iv)
        print("returning msg of size ", len(msg))
        return msg,None

#

def send_request_message(sock,cam_addr,msg_id,message, aes_key, aes_iv, cam_pub_key):
    payload_bytes = bytearray(message.encode('utf-8'))
    final = generate_command_message(cam_pub_key, payload_bytes, aes_key, aes_iv, transaction_id=msg_id, message_type=5)
    return final
    '''
    message_len = len(payload_bytes)

    # Construct message header of type 5 (Request)
    message_header = format_peer_message_header(
        msg_id, 5, message_len, 1, 1)

    # Not needed if the way camera parses data is modified
    AES_bytes = bytearray(aes_key) + bytearray(aes_iv) + get_byte(15, 1)

    # Encrypt using camera's public key
    message_bytes = security.encrypt_rsa(
        message_header+AES_bytes+payload_bytes, cam_pub_key)
    final = generate_encrypt_header(1, 1, 1) + bytearray(message_bytes)
    print("Sent Packet Request for " +
            str(payload_bytes)[-10:], " to ", cam_addr)
    # Send the request
    #send_ready = select.select([], [sock], [], 1)
    #if send_ready[1]:
    #    sent = sock.sendto(final, cam_addr)
    return final
    '''

def send_hello(sock, preferred_send_date, DELTA, server_addr):
    send_ready = select.select([], [sock], [], 1)
    if send_ready[1]:
        if preferred_send_date is not None:
            print("preferred send date is ", preferred_send_date)
            diffs = compare_datetime(preferred_send_date)
            print("diffs 3 are ", diffs, DELTA)
            time.sleep(abs(diffs+DELTA))
        sent = sock.sendto("HELLO".encode(), server_addr)
        print("hello sent...")
        #print("diff time was ", diffs)

def send_hello1(sock, peer_address, PREFERRED_UDP_PORT,PUB_KEY,key,iv, preferred_send_date=None,DELTA=0):
    try:
        # Received Pure Hello Sending Hello1
        # 3970643 4 1/1 32/nKEYIV/n[PAYLOAD]
        hello1_msg = generate_hello1_message(PREFERRED_UDP_PORT)
        payload_bytes = bytearray(str(PREFERRED_UDP_PORT).encode('utf-8'))
        # KEY + IV/n
        AES_bytes = bytearray(key) + bytearray(iv) + get_byte(15, 1)
        message_bytes = security.encrypt_rsa(
            hello1_msg+AES_bytes+payload_bytes, PUB_KEY)
        final = generate_encrypt_header(1,1,1) + bytearray(message_bytes)
        hello1_packet = final
        send_ready = select.select([], [sock], [], 1)
        if send_ready[1]:
            diff = 0
            if preferred_send_date is not None:
                diff = compare_time(preferred_send_date)
                print("diffs 2 are ", diff, DELTA)
                time.sleep(abs(diff+DELTA))
            sent = sock.sendto(hello1_packet, peer_address)
            print("preferred_send_date: ", preferred_send_date)
            print("diff: ", diff)
            print("DELTA: ", DELTA)
            print("Sleep Time: ", diff+DELTA)
        #return hello1_packet

    except Exception as err:
        print("Exception in format_hello1", err)


def send_hello2(sock, peer_address, PREFERRED_UDP_PORT,PUB_KEY,key,iv,DELTA):
    try:
        hello2_msg = generate_hello2_message(PREFERRED_UDP_PORT)
        payload = str(PREFERRED_UDP_PORT)+","+datetime_to_str(datetime.datetime.utcnow())+","+str(DELTA)    # "PORT,Date,DELTA"
        payload_bytes = bytearray(payload.encode('utf-8'))
        encrypted_bytes = generate_encrypt_header(1,1,1)+ bytearray(security.encrypt_aes(hello2_msg+payload_bytes, key, iv))
   
        send_ready = select.select([], [sock], [], 1)
        if send_ready[1]:
            sent = sock.sendto(encrypted_bytes, peer_address)
            print("sent hello 2") 
    except Exception as err:
        print("Exception in format_hello2", err)


def send_hello3(sock, peer_address,DEVICE_PREFERRED_UDP_PORT,PUB_KEY,key,iv,preferred_future_send_date):
    try:
        hello3_msg = generate_hello3_message(DEVICE_PREFERRED_UDP_PORT)
        payload = str(DEVICE_PREFERRED_UDP_PORT)+","+datetime_to_str(preferred_future_send_date)    # "PORT,Date"
        payload_bytes = bytearray(payload.encode('utf-8'))

        if PUB_KEY == 0: # Camera is sending hello3 to Device
            encrypted_bytes = generate_encrypt_header(1,1,1) + bytearray(security.encrypt_aes(hello3_msg+payload_bytes, key, iv))
        else:           # Device is sending hello3 to Camera
            AES_bytes = bytearray(key) + bytearray(iv) + get_byte(15, 1)
            message_bytes = security.encrypt_rsa(
                hello3_msg+AES_bytes+payload_bytes, PUB_KEY)
            encrypted_bytes = generate_encrypt_header(1,1,1) + bytearray(message_bytes)
        
        send_ready = select.select([], [sock], [], 1)
        if send_ready[1]:
            sent = sock.sendto(encrypted_bytes, peer_address)
            print("sent hello 3")
        
    except Exception as err:
        print("Exception in format_hello3", err)
