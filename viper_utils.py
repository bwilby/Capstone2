#!/bin/python

"""
General functions used by both tester client and camera emulator
"""

import base64
from hashlib import sha1
import socket
from select import select
import struct
import string
import datetime
import random
import xml.etree.ElementTree as ET

MULTICAST_TTL = 2
CRLF = "\r\n"


def split_http(http: str) -> tuple[dict, str]:
    """Splits received HTTP message into header values & XML"""
    parts = http.split("\r\n\r\n", 1)

    header = parse_header(parts[0])

    # TODO: Decide how to parse XML files, strings so formatting is easier or ETs
    #xml = ET.fromstring(parts[1])
    xml = parts[1]

    return (header, xml)


def combine_http(header: dict, xml: str) -> str:
    """Re-combines header values & XML into a valid HTTP message"""
    # TODO: Decide how to parse XML files, strings so formatting is easier or ETs
    #xml_string = ET.tostring(ET.indent(xml)).decode()
    xml_string = xml

    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages/httpmsgstructure2.png
    combined = header["STARTLINE"] + "\r\n"
    del header["STARTLINE"]
    combined += "\r\n".join([f"{k}: {header[k]}" for k in header]) + "\r\n"
    combined += f"Content-Length: {len(xml_string)}\r\n\r\n"

    combined += xml_string

    return combined


def parse_header(header: str) -> dict:
    """Extract key/value pairs from a header string"""
    values = {}
    lines = header.split("\r\n")

    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages/httpmsgstructure2.png
    values["STARTLINE"] = lines[0]
    del lines[0]

    for line in lines:
        keyval = line.split(": ", 1)
        if len(keyval) == 2:
            key = keyval[0].lower()
            val = keyval[1]
            # `Content-Length` is calculated upon XML generation, no need to store it
            if key != "content-length":
                values[key] = val

    return values


def check_xml_values(tree: ET, tags: dict) -> (bool, dict):
    """Check that all tags exist, and their values if they're not `None`"""
    results = {}
    allok = True

    for tag in tags:
        expected = tags[tag]
        value = [e.text for e in find_xml_value(tree, tag)]

        # If expected result is `None`, just check for tag existence
        if expected == value or expected == None and len(value) != 0:
            results[tag] = True
        else:
            results[tag] = False
            allok = False

    return allok, results


def find_xml_value(tree: ET, tag: str) -> list[ET]:
    """Get a specific XML tag if it exists, or an array if there are multiple"""
    #namespace = {"soap": "http://www.w3.org/2003/05/soap-envelope", "tds": "http://www.onvif.org/ver10/device/wsdl", "tt": "http://www.onvif.org/ver10/schema", "s": "http://www.w3.org/2001/XMLSchema"}
    namespace = {
        "soap": "http://www.w3.org/2003/05/soap-envelope",
        "xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xsd": "http://www.w3.org/2001/XMLSchema",
        "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
        "wsdd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
        "chan": "http://schemas.microsoft.com/ws/2005/02/duplex",
        "wsa5": "http://www.w3.org/2005/08/addressing",
        "c14n": "http://www.w3.org/2001/10/xml-exc-c14n#",
        "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        "xenc": "http://www.w3.org/2001/04/xmlenc#",
        "wsc": "http://schemas.xmlsoap.org/ws/2005/02/sc",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
        "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        "xmime": "http://tempuri.org/xmime.xsd",
        "xop": "http://www.w3.org/2004/08/xop/include",
        "rt7": "http://www.realtime-7.com/ver1/wsdl",
        "tt": "http://www.onvif.org/ver10/schema",
        "wsnt": "http://docs.oasis-open.org/wsn/b-2",
        "wsrfbf": "http://docs.oasis-open.org/wsrf/bf-2",
        "wstop": "http://docs.oasis-open.org/wsn/t-1",
        "dn": "http://www.onvif.org/ver10/network/wsdl",
        "tds": "http://www.onvif.org/ver10/device/wsdl",
        "tptz": "http://www.onvif.org/ver20/ptz/wsdl",
        "trt": "http://www.onvif.org/ver10/media/wsdl"
    }

    return tree.findall(f".//{tag}", namespace)


def read_full_file(path: str) -> str:
    """Reads the entire contents of a file"""
    with open(path, "r", newline="") as file:
        text = "".join(file.readlines())

    return text


def get_auth(username: str, password: str) -> (str, str, str):
    """Generate new authorization values with random nonce for camera access"""
    pool = string.ascii_letters + string.digits + string.punctuation
    created = datetime.datetime.now().isoformat().split(".")[0]
    n64 = "".join(random.choice(pool) for _ in range(22))
    nonce = base64.b64encode(n64.encode("ascii")).decode("ascii")
    pdigest = hash_auth(n64, created, password)
    return pdigest, created, nonce


def hash_auth(n64: str, created: str, password: str) -> str:
    """Hash pre-calculated authorization values for both generating and validating"""
    base = (n64 + created + password).encode("ascii")
    return base64.b64encode(sha1(base).digest()).decode("ascii")


def get_mcast_sender():
    """Set up a multicast UDP socket to send broadcasts"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
    return sock


def get_mcast_listener(grp: str, port: int):
    """Set up a multicast UDP socket to receive broadcasts"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Windows doesn't like sock.bind((grp, port))
    sock.bind(("", port))

    mreq = struct.pack("4sl", socket.inet_aton(grp), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock


def sock_open(sock) -> bool:
    """Checks if a socket is open"""
    ready = select([sock], [], [], 0.1)

    # b"" returned, meaning socket is down
    if ready[0]:
        if not sock.recv(0):
            return False

    # Still waiting for input, meaning socket is up
    return True

