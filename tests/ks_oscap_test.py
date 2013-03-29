"""Module with tests for the ks/oscap.py module."""

import unittest
from org_fedora_oscap.ks.oscap import OSCAPdata

class ParsingTest(unittest.TestCase):
    def setUp(self):
        self.oscap_data = OSCAPdata("org_fedora_oscap")

    def parsing_test(self):
        for line in ["content-type = datastream\n",
                     "content-url = https://example.com/hardening.xml\n",
                     "datastream-id = id_datastream_1\n",
                     "xccdf-id = id_xccdf_new\n",
                     "profile = Web Server\n",
                     ]:
            self.oscap_data.handle_line(line)

        self.assertEqual(self.oscap_data.content_type, "datastream")
        self.assertEqual(self.oscap_data.content_url,
                         "https://example.com/hardening.xml")
        self.assertEqual(self.oscap_data.datastream_id, "id_datastream_1")
        self.assertEqual(self.oscap_data.xccdf_id, "id_xccdf_new")
        self.assertEqual(self.oscap_data.profile_id, "Web Server")
