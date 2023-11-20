import xml.etree.ElementTree as ET

with open("1_dev_mngt_CreateUsers.req", "r") as file:

    header, xml = ("".join(file.readlines()).split('\n' + '\n', 1))
tree = ET.fromstring(xml)
namespace = {'tds': 'http://www.onvif.org/ver10/device/wsdl', 'tt': 'http://www.onvif.org/ver10/schema', 's': 'http://www.w3.org/2001/XMLSchema'}
print([user[0].text for user in tree.findall(".//tds:User", namespace)])

tree.findall(".//tds:User", namespace)[0][0].text = "test"
print([user[0].text for user in tree.findall(".//tds:User", namespace)])

# XML validation
def is_valid_xml(xml_string):
    try:
        ET.fromstring(xml_string)
        return True
    except ET.ParseError:
        return False

# Check for required tags
def has_required_tags(xml_string, required_tags):
    root = ET.fromstring(xml_string)
    for tag in required_tags:
        if root.find(".//{}".format(tag)) is None:
            return False, tag
    return True, ""

# Check the payload
def check_payload(xml_string, tag, expected_payload):
    root = ET.fromstring(xml_string)
    actual_payload = root.find(".//{}".format(tag)).text
    return actual_payload == expected_payload
