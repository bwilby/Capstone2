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
