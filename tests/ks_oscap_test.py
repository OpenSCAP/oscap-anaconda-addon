"""Module with tests for the ks/oscap.py module."""

import unittest
from org_fedora_oscap.ks.oscap import OSCAPdata

class ParsingTest(unittest.TestCase):
    def setUp(self):
        self.oscap_data = OSCAPdata("org_fedora_oscap")
        for line in ["content-type = datastream\n",
                     "content-url = https://example.com/hardening.xml\n",
                     "datastream-id = id_datastream_1\n",
                     "xccdf-id = id_xccdf_new\n",
                     "xccdf-path = /usr/share/oscap/xccdf.xml",
                     "cpe-path = /usr/share/oscap/cpe.xml",
                     "profile = Web Server\n",
                     ]:
            self.oscap_data.handle_line(line)

    def parsing_test(self):
        self.assertEqual(self.oscap_data.content_type, "datastream")
        self.assertEqual(self.oscap_data.content_url,
                         "https://example.com/hardening.xml")
        self.assertEqual(self.oscap_data.datastream_id, "id_datastream_1")
        self.assertEqual(self.oscap_data.xccdf_id, "id_xccdf_new")
        self.assertEqual(self.oscap_data.xccdf_path, "/usr/share/oscap/xccdf.xml")
        self.assertEqual(self.oscap_data.cpe_path, "/usr/share/oscap/cpe.xml")
        self.assertEqual(self.oscap_data.profile_id, "Web Server")

    def str_test(self):
        str_ret = str(self.oscap_data)
        self.assertEqual(str_ret,
                         "%addon org_fedora_oscap\n"
                         "    content-type = datastream\n"
                         "    content-url = https://example.com/hardening.xml\n"
                         "    datastream-id = id_datastream_1\n"
                         "    xccdf-id = id_xccdf_new\n"
                         "    xccdf-path = /usr/share/oscap/xccdf.xml\n"
                         "    cpe-path = /usr/share/oscap/cpe.xml\n"
                         "    profile = Web Server\n"
                         "%end"
                         )
    def str_parse_test(self):
        self.oscap_data2 = OSCAPdata("org_fedora_oscap")
        str_ret = str(self.oscap_data)
        for line in str_ret.splitlines()[1:-1]:
            self.oscap_data2.handle_line(line)

        str_ret2 = str(self.oscap_data)
        self.assertEqual(str_ret, str_ret2)
