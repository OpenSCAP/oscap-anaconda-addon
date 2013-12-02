"""Module with tests for the ks/oscap.py module."""

import unittest
from pykickstart.errors import KickstartValueError
from org_fedora_oscap.ks.oscap import OSCAPdata
from org_fedora_oscap import common

class ParsingTest(unittest.TestCase):
    def setUp(self):
        self.oscap_data = OSCAPdata("org_fedora_oscap")
        for line in ["content-type = datastream\n",
                     "content-url = \"https://example.com/hardening.xml\"\n",
                     "datastream-id = id_datastream_1\n",
                     "xccdf-id = id_xccdf_new\n",
                     "xccdf-path = /usr/share/oscap/xccdf.xml",
                     "cpe-path = /usr/share/oscap/cpe.xml",
                     "profile = \"Web Server\"\n",
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
        self.assertEqual(self.oscap_data.content_name, "hardening.xml")

    def properties_test(self):
        self.assertEqual(self.oscap_data.preinst_content_path,
                         common.INSTALLATION_CONTENT_DIR + "/" +
                         self.oscap_data.content_name)

        self.assertEqual(self.oscap_data.postinst_content_path,
                         common.TARGET_CONTENT_DIR + "/" +
                         self.oscap_data.content_name)

        self.assertEqual(self.oscap_data.raw_preinst_content_path,
                         common.INSTALLATION_CONTENT_DIR + "/" +
                         self.oscap_data.content_name)

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

class IncompleteDataTest(unittest.TestCase):
    def setUp(self):
        self.oscap_data = OSCAPdata("org_fedora_oscap")

    def nothing_given_test(self):
        with self.assertRaises(KickstartValueError):
            self.oscap_data.finalize()

    def no_content_type_test(self):
        for line in ["content-url = http://example.com/test_ds.xml",
                     "profile = Web Server",
                     ]:
            self.oscap_data.handle_line(line)
        with self.assertRaises(KickstartValueError):
            self.oscap_data.finalize()

    def no_content_url_test(self):
        for line in ["content-type = datastream",
                     "profile = Web Server",
                     ]:
            self.oscap_data.handle_line(line)

        with self.assertRaises(KickstartValueError):
            self.oscap_data.finalize()

    def no_profile_test(self):
        for line in ["content-url = http://example.com/test_ds.xml",
                     "content-type = datastream",
                     ]:
            self.oscap_data.handle_line(line)

        with self.assertRaises(KickstartValueError):
            self.oscap_data.finalize()

class InvalidDataTest(unittest.TestCase):
    def setUp(self):
        self.oscap_data = OSCAPdata("org_fedora_oscap")

    def rpm_without_path_test(self):
        for line in ["content-url = http://example.com/oscap_content.rpm",
                     "content-type = RPM",
                     "profile = Web Server",
                     ]:
            self.oscap_data.handle_line(line)

        with self.assertRaises(KickstartValueError):
            self.oscap_data.finalize()

    def rpm_with_wrong_suffix_test(self):
        for line in ["content-url = http://example.com/oscap_content.xml",
                     "content-type = RPM",
                     "profile = Web Server",
                     ]:
            self.oscap_data.handle_line(line)

        with self.assertRaises(KickstartValueError):
            self.oscap_data.finalize()

    def archive_without_path_test(self):
        for line in ["content-url = http://example.com/oscap_content.tar",
                     "content-type = archive",
                     "profile = Web Server",
                     ]:
            self.oscap_data.handle_line(line)

        with self.assertRaises(KickstartValueError):
            self.oscap_data.finalize()

    def unsupported_archive_type_test(self):
        for line in ["content-url = http://example.com/oscap_content.tbz",
                     "content-type = archive",
                     "profile = Web Server",
                     "xccdf-path = xccdf.xml"
                     ]:
            self.oscap_data.handle_line(line)

        with self.assertRaises(KickstartValueError):
            self.oscap_data.finalize()

class EverythingOKtest(unittest.TestCase):
    def setUp(self):
        self.oscap_data = OSCAPdata("org_fedora_oscap")

    def enough_for_ds_test(self):
        for line in ["content-url = http://example.com/test_ds.xml",
                     "content-type = datastream",
                     "profile = Web Server",
                     ]:
            self.oscap_data.handle_line(line)

        self.oscap_data.finalize()

    def enough_for_rpm_test(self):
        for line in ["content-url = http://example.com/oscap_content.rpm",
                     "content-type = RPM",
                     "profile = Web Server",
                     "xccdf-path = /usr/share/oscap/xccdf.xml"
                     ]:
            self.oscap_data.handle_line(line)

        self.oscap_data.finalize()

    def enough_for_archive_test(self):
        for line in ["content-url = http://example.com/oscap_content.tar",
                     "content-type = archive",
                     "profile = Web Server",
                     "xccdf-path = /usr/share/oscap/xccdf.xml"
                     ]:
            self.oscap_data.handle_line(line)

        self.oscap_data.finalize()

class ArchiveHandlingTest(unittest.TestCase):
    """Tests for handling archives."""

    def setUp(self):
        self.oscap_data = OSCAPdata("org_fedora_oscap")

    def archive_preinst_content_path_test(self):
        for line in ["content-url = http://example.com/oscap_content.tar",
                     "content-type = archive",
                     "profile = Web Server",
                     "xccdf-path = oscap/xccdf.xml"
                     ]:
            self.oscap_data.handle_line(line)

        self.oscap_data.finalize()

        # content_name should be the archive's name
        self.assertEqual(self.oscap_data.content_name, "oscap_content.tar")

        # content path should end with the xccdf path
        self.assertTrue(self.oscap_data.preinst_content_path.endswith(
                                                         "oscap/xccdf.xml"))

    def ds_preinst_content_path_test(self):
        for line in ["content-url = http://example.com/scap_content.xml",
                     "content-type = datastream",
                     "profile = Web Server",
                     ]:
            self.oscap_data.handle_line(line)

        self.oscap_data.finalize()

        # both content_name and content path should point to the data stream XML
        self.assertEqual(self.oscap_data.content_name, "scap_content.xml")
        self.assertTrue(self.oscap_data.preinst_content_path.endswith(
                                                         "scap_content.xml"))

    def archive_raw_content_paths_test(self):
        for line in ["content-url = http://example.com/oscap_content.tar",
                     "content-type = archive",
                     "profile = Web Server",
                     "xccdf-path = oscap/xccdf.xml"
                     ]:
            self.oscap_data.handle_line(line)

        self.oscap_data.finalize()

        # content_name should be the archive's name
        self.assertEqual(self.oscap_data.content_name, "oscap_content.tar")

        # content path should end with the archive's name
        self.assertTrue(self.oscap_data.raw_preinst_content_path.endswith(
                                                         "oscap_content.tar"))
        self.assertTrue(self.oscap_data.raw_postinst_content_path.endswith(
                                                         "oscap_content.tar"))

    def ds_raw_content_paths_test(self):
        for line in ["content-url = http://example.com/scap_content.xml",
                     "content-type = datastream",
                     "profile = Web Server",
                     ]:
            self.oscap_data.handle_line(line)

        self.oscap_data.finalize()

        # content_name and content paths should all point to the data stream XML
        self.assertEqual(self.oscap_data.content_name, "scap_content.xml")
        self.assertTrue(self.oscap_data.raw_preinst_content_path.endswith(
                                                         "scap_content.xml"))
        self.assertTrue(self.oscap_data.raw_postinst_content_path.endswith(
                                                         "scap_content.xml"))

