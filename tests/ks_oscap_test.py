"""Module with tests for the ks/oscap.py module."""

import unittest
import os
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
                     "content-path = /usr/share/oscap/testing_ds.xml",
                     "cpe-path = /usr/share/oscap/cpe.xml",
                     "tailoring-path = /usr/share/oscap/tailoring.xml",
                     "profile = \"Web Server\"\n",
                     ]:
            self.oscap_data.handle_line(line)

    def parsing_test(self):
        self.assertEqual(self.oscap_data.content_type, "datastream")
        self.assertEqual(self.oscap_data.content_url,
                         "https://example.com/hardening.xml")
        self.assertEqual(self.oscap_data.datastream_id, "id_datastream_1")
        self.assertEqual(self.oscap_data.xccdf_id, "id_xccdf_new")
        self.assertEqual(self.oscap_data.content_path,
                         "/usr/share/oscap/testing_ds.xml")
        self.assertEqual(self.oscap_data.cpe_path, "/usr/share/oscap/cpe.xml")
        self.assertEqual(self.oscap_data.profile_id, "Web Server")
        self.assertEqual(self.oscap_data.content_name, "hardening.xml")
        self.assertEqual(self.oscap_data.tailoring_path,
                         "/usr/share/oscap/tailoring.xml")

    def properties_test(self):
        self.assertEqual(self.oscap_data.preinst_content_path,
                         common.INSTALLATION_CONTENT_DIR +
                         self.oscap_data.content_name)

        self.assertEqual(self.oscap_data.postinst_content_path,
                         common.TARGET_CONTENT_DIR +
                         self.oscap_data.content_name)

        self.assertEqual(self.oscap_data.raw_preinst_content_path,
                         common.INSTALLATION_CONTENT_DIR +
                         self.oscap_data.content_name)

        self.assertEqual(self.oscap_data.preinst_tailoring_path,
                         os.path.normpath(common.INSTALLATION_CONTENT_DIR +
                                          self.oscap_data.tailoring_path))

        self.assertEqual(self.oscap_data.postinst_tailoring_path,
                         os.path.normpath(common.TARGET_CONTENT_DIR +
                                          self.oscap_data.tailoring_path))

    def str_test(self):
        str_ret = str(self.oscap_data)
        self.assertEqual(str_ret,
                         "%addon org_fedora_oscap\n"
                         "    content-type = datastream\n"
                         "    content-url = https://example.com/hardening.xml\n"
                         "    datastream-id = id_datastream_1\n"
                         "    xccdf-id = id_xccdf_new\n"
                         "    content-path = /usr/share/oscap/testing_ds.xml\n"
                         "    cpe-path = /usr/share/oscap/cpe.xml\n"
                         "    tailoring-path = /usr/share/oscap/tailoring.xml\n"
                         "    profile = Web Server\n"
                         "%end\n\n"
                         )

    def str_parse_test(self):
        self.oscap_data2 = OSCAPdata("org_fedora_oscap")
        str_ret = str(self.oscap_data)
        for line in str_ret.splitlines()[1:-1]:
            if "%end" not in line:
                self.oscap_data2.handle_line(line)

        str_ret2 = str(self.oscap_data)
        self.assertEqual(str_ret, str_ret2)


class BackwardCompatibilityParsingTest(unittest.TestCase):
    def setUp(self):
        self.oscap_data = OSCAPdata("org_fedora_oscap")
        for line in ["content-type = datastream\n",
                     "content-url = \"https://example.com/hardening.xml\"\n",
                     "datastream-id = id_datastream_1\n",
                     "xccdf-id = id_xccdf_new\n",
                     "xccdf-path = /usr/share/oscap/xccdf.xml",
                     "cpe-path = /usr/share/oscap/cpe.xml",
                     "tailoring-path = /usr/share/oscap/tailoring.xml",
                     "profile = \"Web Server\"\n",
                     ]:
            self.oscap_data.handle_line(line)

    def str_test(self):
        str_ret = str(self.oscap_data)
        self.assertEqual(str_ret,
                         "%addon org_fedora_oscap\n"
                         "    content-type = datastream\n"
                         "    content-url = https://example.com/hardening.xml\n"
                         "    datastream-id = id_datastream_1\n"
                         "    xccdf-id = id_xccdf_new\n"
                         "    content-path = /usr/share/oscap/xccdf.xml\n"
                         "    cpe-path = /usr/share/oscap/cpe.xml\n"
                         "    tailoring-path = /usr/share/oscap/tailoring.xml\n"
                         "    profile = Web Server\n"
                         "%end\n\n"
                         )


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

        self.oscap_data.finalize()
        self.assertEqual(self.oscap_data.profile_id, "default")


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

        # both content_name and content path should point to the data stream
        # XML
        self.assertEqual(self.oscap_data.content_name, "scap_content.xml")
        self.assertTrue(self.oscap_data.preinst_content_path.endswith(
                                                         "scap_content.xml"))

    def archive_raw_content_paths_test(self):
        for line in ["content-url = http://example.com/oscap_content.tar",
                     "content-type = archive",
                     "profile = Web Server",
                     "xccdf-path = oscap/xccdf.xml",
                     "tailoring-path = oscap/tailoring.xml",
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

        # tailoring paths should be returned properly
        self.assertEqual(self.oscap_data.preinst_tailoring_path,
                         common.INSTALLATION_CONTENT_DIR +
                         self.oscap_data.tailoring_path)

        self.assertEqual(self.oscap_data.postinst_tailoring_path,
                         common.TARGET_CONTENT_DIR +
                         self.oscap_data.tailoring_path)

    def rpm_raw_content_paths_test(self):
        for line in ["content-url = http://example.com/oscap_content.rpm",
                     "content-type = rpm",
                     "profile = Web Server",
                     "xccdf-path = /usr/share/oscap/xccdf.xml",
                     "tailoring-path = /usr/share/oscap/tailoring.xml",
                     ]:
            self.oscap_data.handle_line(line)

        self.oscap_data.finalize()

        # content_name should be the rpm's name
        self.assertEqual(self.oscap_data.content_name, "oscap_content.rpm")

        # content path should end with the rpm's name
        self.assertTrue(self.oscap_data.raw_preinst_content_path.endswith(
                                                         "oscap_content.rpm"))
        self.assertTrue(self.oscap_data.raw_postinst_content_path.endswith(
                                                         "oscap_content.rpm"))

        # content paths should be returned as expected
        self.assertEqual(self.oscap_data.preinst_content_path,
                         os.path.normpath(common.INSTALLATION_CONTENT_DIR +
                                          self.oscap_data.content_path))

        # when using rpm, content_path doesn't change for the post-installation
        # phase
        self.assertEqual(self.oscap_data.postinst_content_path,
                         self.oscap_data.content_path)

    def ds_raw_content_paths_test(self):
        for line in ["content-url = http://example.com/scap_content.xml",
                     "content-type = datastream",
                     "profile = Web Server",
                     ]:
            self.oscap_data.handle_line(line)

        self.oscap_data.finalize()

        # content_name and content paths should all point to the data stream
        # XML
        self.assertEqual(self.oscap_data.content_name, "scap_content.xml")
        self.assertTrue(self.oscap_data.raw_preinst_content_path.endswith(
                                                         "scap_content.xml"))
        self.assertTrue(self.oscap_data.raw_postinst_content_path.endswith(
                                                         "scap_content.xml"))


class FingerprintTests(unittest.TestCase):
    """Tests for fingerprint pre-processing."""

    def setUp(self):
        self.oscap_data = OSCAPdata("org_fedora_oscap")

    def valid_fingerprints_test(self):
        self.oscap_data.handle_line("fingerprint = %s" % ("a" * 32))
        self.oscap_data.handle_line("fingerprint = %s" % ("a" * 40))
        self.oscap_data.handle_line("fingerprint = %s" % ("a" * 56))
        self.oscap_data.handle_line("fingerprint = %s" % ("a" * 64))
        self.oscap_data.handle_line("fingerprint = %s" % ("a" * 96))
        self.oscap_data.handle_line("fingerprint = %s" % ("a" * 128))

    def invalid_fingerprints_test(self):
        # invalid character
        with self.assertRaisesRegexp(KickstartValueError,
                                     "Unsupported or invalid fingerprint"):
            self.oscap_data.handle_line("fingerprint = %s?" % ("a" * 31))

        # invalid lengths (odd and even)
        with self.assertRaisesRegexp(KickstartValueError,
                                     "Unsupported fingerprint"):
            self.oscap_data.handle_line("fingerprint = %s" % ("a" * 31))
        with self.assertRaisesRegexp(KickstartValueError,
                                     "Unsupported fingerprint"):
            self.oscap_data.handle_line("fingerprint = %s" % ("a" * 41))
        with self.assertRaisesRegexp(KickstartValueError,
                                     "Unsupported fingerprint"):
            self.oscap_data.handle_line("fingerprint = %s" % ("a" * 54))
        with self.assertRaisesRegexp(KickstartValueError,
                                     "Unsupported fingerprint"):
            self.oscap_data.handle_line("fingerprint = %s" % ("a" * 66))
        with self.assertRaisesRegexp(KickstartValueError,
                                     "Unsupported fingerprint"):
            self.oscap_data.handle_line("fingerprint = %s" % ("a" * 98))
        with self.assertRaisesRegexp(KickstartValueError,
                                     "Unsupported fingerprint"):
            self.oscap_data.handle_line("fingerprint = %s" % ("a" * 124))
