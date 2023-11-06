#!/bin/python

"""
Tests getting camera objects, video, events, and image
"""

import viper_utils
import logging
import xml.etree.ElementTree as ET

RECV_SIZE = 10240

# test_getting_camera_objects
def test_getting_camera_objects(sock) -> tuple[bool, str]:
    try:
        # Construct request
        auth = viper_utils.get_auth("ADMIN", "password")
        req_header, req_xml = viper_utils.split_http(viper_utils.read_full_file("http_templates/get_camera_objects.req"))

        req_xml = req_xml.format(
            username="ADMIN", password_digest=auth[0], password_nonce=auth[2], password_created=auth[1]
        )

        request = viper_utils.combine_http(req_header, req_xml)
        logging.debug(f"Sending\n{request}")

        # Send request & get response
        sock.send(request.encode())
        response = sock.recv(RECV_SIZE).decode("utf-8")
        logging.debug(f"Received\n{response}")
        res_header, res_xml = viper_utils.split_http(response)

        # Check that XML structure is correct
        res_xml_et = ET.fromstring(res_xml)
        exp_header, exp_xml = viper_utils.split_http(viper_utils.read_full_file("http_templates/get_camera_objects.res"))
        exp_xml_et = ET.fromstring(exp_xml)
        return (viper_utils.validate_xml_structure(exp_xml_et, res_xml_et), "")

    except Exception as e:
        logging.error(e)
        return (False, e)

# test_getting_camera_video
def test_getting_camera_video(sock) -> tuple[bool, str]:
    try:
        # Construct request
        auth = viper_utils.get_auth("ADMIN", "password")
        req_header, req_xml = viper_utils.split_http(viper_utils.read_full_file("http_templates/get_camera_video.req"))

        req_xml = req_xml.format(
            username="ADMIN", password_digest=auth[0], password_nonce=auth[2], password_created=auth[1],
            seq="SEQUENCE_NUMBER"  
        )

        request = viper_utils.combine_http(req_header, req_xml)
        logging.debug(f"Sending\n{request}")

        # Send request & get response
        sock.send(request.encode())
        response = sock.recv(RECV_SIZE).decode("utf-8")
        logging.debug(f"Received\n{response}")
        res_header, res_xml = viper_utils.split_http(response)

        # Check that XML structure is correct and contains the Video tag
        res_xml_et = ET.fromstring(res_xml)
        exp_header, exp_xml = viper_utils.split_http(viper_utils.read_full_file("http_templates/get_camera_video.res"))
        exp_xml_et = ET.fromstring(exp_xml)

        # Ensure structure is correct
        if not viper_utils.validate_xml_structure(exp_xml_et, res_xml_et):
            return (False, "XML structure mismatch")

        # Further validation can be done to ensure the Video tag contains valid data
        video_tag = res_xml_et.find('.//rt7:Video', namespaces={'rt7': 'http://www.realtime-7.com/ver1/wsdl'})
        if video_tag is None or not video_tag.text:
            return (False, "Missing or empty Video tag")

        return (True, "")

    except Exception as e:
        logging.error(e)
        return (False, str(e))

# test_getting_camera_events
def test_getting_camera_events(sock) -> tuple[bool, str]:
    try:
        # Construct request
        auth = viper_utils.get_auth("ADMIN", "password")
        req_header, req_xml = viper_utils.split_http(viper_utils.read_full_file("http_templates/get_camera_events.req"))

        req_xml = req_xml.format(
            username="ADMIN", password_digest=auth[0], password_nonce=auth[2], password_created=auth[1],
            seq="SEQUENCE_NUMBER",
            num="NUM_VALUE",
            order="ORDER_VALUE" 
        )

        request = viper_utils.combine_http(req_header, req_xml)
        logging.debug(f"Sending\n{request}")

        # Send request & get response
        sock.send(request.encode())
        response = sock.recv(RECV_SIZE).decode("utf-8")
        logging.debug(f"Received\n{response}")
        res_header, res_xml = viper_utils.split_http(response)

        # Check that XML structure is correct and contains the events
        res_xml_et = ET.fromstring(res_xml)
        exp_header, exp_xml = viper_utils.split_http(viper_utils.read_full_file("http_templates/get_camera_events.res"))
        exp_xml_et = ET.fromstring(exp_xml)

        # Ensure structure is correct
        if not viper_utils.validate_xml_structure(exp_xml_et, res_xml_et):
            return (False, "XML structure mismatch")

        # Further validation can be done to ensure the events are returned correctly
        events = res_xml_et.findall('.//rt7:Events', namespaces={'rt7': 'http://www.realtime-7.com/ver1/wsdl'})
        if not events:
            return (False, "No events found in response")

        return (True, "")

    except Exception as e:
        logging.error(e)
        return (False, str(e))

# test_getting_camera_image
def test_getting_camera_image(sock) -> tuple[bool, str]:
    try:
        # Construct request
        auth = viper_utils.get_auth("ADMIN", "password")
        req_header, req_xml = viper_utils.split_http(viper_utils.read_full_file("http_templates/get_camera_image.req"))

        req_xml = req_xml.format(
            username="ADMIN", password_digest=auth[0], password_nonce=auth[2], password_created=auth[1]
        )

        request = viper_utils.combine_http(req_header, req_xml)
        logging.debug(f"Sending\n{request}")

        # Send request & get response
        sock.send(request.encode())
        response = sock.recv(RECV_SIZE).decode("utf-8")
        logging.debug(f"Received\n{response}")
        res_header, res_xml = viper_utils.split_http(response)

        # Check that XML structure is correct and contains the CameraImage tag
        res_xml_et = ET.fromstring(res_xml)
        exp_header, exp_xml = viper_utils.split_http(viper_utils.read_full_file("http_templates/get_camera_image.res"))
        exp_xml_et = ET.fromstring(exp_xml)

        # Ensure structure is correct
        if not viper_utils.validate_xml_structure(exp_xml_et, res_xml_et):
            return (False, "XML structure mismatch")

        # Further validation can be done to ensure the CameraImage tag contains valid data
        camera_image_tag = res_xml_et.find('.//rt7:CameraImage', namespaces={'rt7': 'http://www.realtime-7.com/ver1/wsdl'})
        if camera_image_tag is None or not camera_image_tag.text:
            return (False, "Missing or empty CameraImage tag")

        return (True, "")

    except Exception as e:
        logging.error(e)
        return (False, str(e))


TESTS = [
    test_getting_camera_objects,
    test_getting_camera_video,
    test_getting_camera_events,
    test_getting_camera_image
]

