#!/bin/python

"""
Primary camera-testing client that listens to camera announcements and sends scripted requests
"""

import viper_utils
import socket
import os
import threading
import uuid
import logging
import time
import re
from select import select
import xml.etree.ElementTree as ET
import importlib.util

# https://docs.python.org/3/howto/logging.html
logging.basicConfig(level=logging.INFO, format="[%(levelname)s]   \t%(asctime)s   \t%(message)s", datefmt="%Y-%m-%d %H:%M:%S")

TESTER_IP = "127.0.0.1"
TESTER_PORT = 3700

# https://en.wikipedia.org/wiki/Multicast_address#IPv4
MCAST_GRP = "239.255.255.250"
MCAST_SEND_PORT = 3702
MCAST_RECV_PORT = 1000

RECV_SIZE = 10240


def announce_listen(tester_ip: str, tester_port: int, mcast_grp: str, mcast_send_port: int, mcast_recv_port: int):
    """Listen to camera broadcasts and initiate testing cameras"""

    discovery = viper_utils.read_full_file("http_templates/discovery_broadcast.udp")
    discovery = discovery.format(uuid=str(uuid.uuid1()))

    sock = viper_utils.get_mcast_listener(mcast_grp, mcast_recv_port)
    sock.sendto(discovery.encode(), (mcast_grp, mcast_send_port))

    logging.info(f"Broadcast discovery, listening on {mcast_grp}:{mcast_recv_port}")

    while True:
        try:
            # Receive broadcast
            ready = select([sock], [], [], 1)
            if ready[0]:
                broadcast, addr = sock.recvfrom(RECV_SIZE)
                broadcast = broadcast.decode("utf-8")


                if discovery == broadcast:
                    logging.debug("Received own broadcast")
                    continue

                # Broadcast does not contain HTTP header, convert it directly to XML ET
                xml = ET.fromstring(broadcast)
                #recv_ip, recv_port = addr
                camera_ip, camera_port = re.search("(?<=http://)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+(?=/onvif/device_service)", viper_utils.find_xml_value(xml, "wsdd:XAddrs")[0].text).group(0).split(":")
                camera_port = int(camera_port)

                logging.debug(f"Received broadcast from {camera_ip}:{camera_port}\n{broadcast}")

                time.sleep(1)

                # Create thread with `camera_thread()` below and begin testing
                y = threading.Thread(target=camera_thread, args=(camera_ip, camera_port))
                y.start()

        except Exception as e:
            logging.error(e)
def camera_thread(camera_ip: str, camera_port: int):
    """Iterates through a set of tests and sends them to a camera"""
    logging.info(f"Testing camera on {camera_ip}:{camera_port}")

    def make_new_socket():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((camera_ip, camera_port))
        return sock

    sock = make_new_socket()

    test_scripts = [script for script in os.listdir("tests") if script.endswith(".py")]
    logging.debug(f"Scripts: {test_scripts}")

    for script in test_scripts:
        # https://stackoverflow.com/a/59032021
        test_spec = importlib.util.spec_from_file_location("test_module", "tests/" + script)
        test_module = importlib.util.module_from_spec(test_spec)
        test_spec.loader.exec_module(test_module)

        for test_function in test_module.TESTS:
            logging.info(f"Testing {script} / {test_function.__name__}")
            if not viper_utils.sock_open(sock):
                logging.debug("Socket closed, re-opening")
                sock = make_new_socket()

            try:
                #test(sock, test_data)
                success, msg = test_function(sock)
                if success:
                    logging.info(f"Test Ok: {msg}")
                else:
                    logging.warning(f"Test Failed: {msg}")

            except Exception as e:
                logging.error(e)

            time.sleep(1)

    logging.info(f"Disconnecting camera on {camera_ip}:{camera_port}")
    sock.close()


def test(sock, request: bytes) -> bool:
    """Script that send a request and compares result from an individual camera"""
    #try:
    logging.debug(f"Sending to camera\n{request}")
    sock.send(request)
    response = sock.recv(RECV_SIZE)
    logging.debug(f"Received response\n{response}")
    return True

    #except:
    #    logging.error(f"Could not connect to camera at {camera_ip}:{camera_port}")
    #    return False


if __name__ == "__main__":
    y = threading.Thread(target=announce_listen, args=(TESTER_IP, TESTER_PORT, MCAST_GRP, MCAST_SEND_PORT, MCAST_RECV_PORT))
    y.start()
    y.join()

