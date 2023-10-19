import viper_utils
import logging
import xml.etree.ElementTree as ET

RECV_SIZE = 10240

def test_getting(sock) -> tuple[bool, str]:
    try:
        # Construct request for camera image retrieval
        auth = viper_utils.get_auth("ADMIN", "password")
        req_header, req_xml = viper_utils.split_http(viper_utils.read_full_file("http_templates/get_camera_image.req"))

        req_xml = req_xml.format(
            username="ADMIN", password_digest=auth[0], password_nonce=auth[2], password_created=auth[1]
        )

        request = viper_utils.combine_http(req_header, req_xml)
        logging.debug(f"Sending camera image retrieval request:\n{request}")

        # Send request & get response
        sock.send(request.encode())
        response = sock.recv(RECV_SIZE).decode("utf-8")
        logging.debug(f"Received camera image retrieval response:\n{response}")
        res_header, res_xml = viper_utils.split_http(response)
        res_xml_et = ET.fromstring(res_xml)

        camera_image_tag = res_xml_et.find('.//rt7:CameraImage', namespaces={'rt7': 'http://www.realtime-7.com/ver1/wsdl'})
        if camera_image_tag is None or not camera_image_tag.text:
            return (False, "Missing or empty CameraImage tag")

        return (True, "")

    except Exception as e:
        logging.error(e)
        return (False, str(e))

TESTS = [test_getting]
