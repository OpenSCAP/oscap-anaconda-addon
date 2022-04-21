"""Module with tests for the ks/oscap.py module."""

import os

from pykickstart.errors import KickstartValueError
import pytest

try:
    from org_fedora_oscap.service.kickstart import OSCAPKickstartData
    from org_fedora_oscap import common
except ImportError as exc:
    pytestmark = pytest.mark.skip(
        "Unable to import modules, possibly due to bad version of Anaconda: {error}"
        .format(error=str(exc)))


@pytest.fixture()
def blank_oscap_data():
    return OSCAPKickstartData()


@pytest.fixture()
def filled_oscap_data(blank_oscap_data):
    oscap_data = blank_oscap_data
    for line in [
            "content-type = datastream\n",
            "content-url = \"https://example.com/hardening.xml\"\n",
            "datastream-id = id_datastream_1\n",
            "xccdf-id = id_xccdf_new\n",
            "content-path = /usr/share/oscap/testing_ds.xml",
            "cpe-path = /usr/share/oscap/cpe.xml",
            "tailoring-path = /usr/share/oscap/tailoring.xml",
            "profile = \"Web Server\"\n",
            ]:
        oscap_data.handle_line(line)
    return oscap_data


def test_parsing(filled_oscap_data):
    data = filled_oscap_data.policy_data
    assert data.content_type == "datastream"
    assert data.content_url == "https://example.com/hardening.xml"
    assert data.datastream_id == "id_datastream_1"
    assert data.xccdf_id == "id_xccdf_new"
    assert data.content_path == "/usr/share/oscap/testing_ds.xml"
    assert data.cpe_path == "/usr/share/oscap/cpe.xml"
    assert data.profile_id == "Web Server"
    assert data.tailoring_path == "/usr/share/oscap/tailoring.xml"


def test_properties(filled_oscap_data):
    data = filled_oscap_data
    assert (data.preinst_content_path
            == common.INSTALLATION_CONTENT_DIR + data.content_name)
    assert (data.postinst_content_path
            == common.TARGET_CONTENT_DIR + data.content_name)
    assert (data.raw_preinst_content_path
            == common.INSTALLATION_CONTENT_DIR + data.content_name)
    assert (data.preinst_tailoring_path
            == os.path.normpath(common.INSTALLATION_CONTENT_DIR + data.policy_data.tailoring_path))
    assert (data.postinst_tailoring_path
            == os.path.normpath(common.TARGET_CONTENT_DIR + data.policy_data.tailoring_path))


def test_str(filled_oscap_data):
    str_ret = str(filled_oscap_data)
    assert (str_ret ==
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


def test_str_parse(filled_oscap_data):
    our_oscap_data = OSCAPKickstartData()

    str_ret = str(filled_oscap_data)
    for line in str_ret.splitlines()[1:-1]:
        if "%end" not in line:
            our_oscap_data.handle_line(line)

    our_str_ret = str(our_oscap_data)
    assert str_ret == our_str_ret


def test_nothing_given(blank_oscap_data):
    with pytest.raises(KickstartValueError):
        blank_oscap_data.handle_end()


def test_no_content_type(blank_oscap_data):
    for line in ["content-url = http://example.com/test_ds.xml",
                 "profile = Web Server",
                 ]:
        blank_oscap_data.handle_line(line)

    with pytest.raises(KickstartValueError):
        blank_oscap_data.handle_end()


def test_no_content_url(blank_oscap_data):
    for line in ["content-type = datastream",
                 "profile = Web Server",
                 ]:
        blank_oscap_data.handle_line(line)

    with pytest.raises(KickstartValueError):
        blank_oscap_data.handle_end()


def test_no_profile(blank_oscap_data):
    for line in ["content-url = http://example.com/test_ds.xml",
                 "content-type = datastream",
                 ]:
        blank_oscap_data.handle_line(line)

    blank_oscap_data.handle_end()
    assert blank_oscap_data.policy_data.profile_id == "default"


def test_rpm_without_path(blank_oscap_data):
    for line in ["content-url = http://example.com/oscap_content.rpm",
                 "content-type = RPM",
                 "profile = Web Server",
                 ]:
        blank_oscap_data.handle_line(line)

    with pytest.raises(KickstartValueError):
        blank_oscap_data.handle_end()


def test_rpm_with_wrong_suffix(blank_oscap_data):
    for line in ["content-url = http://example.com/oscap_content.xml",
                 "content-type = RPM",
                 "profile = Web Server",
                 ]:
        blank_oscap_data.handle_line(line)

    with pytest.raises(KickstartValueError):
        blank_oscap_data.handle_end()


def test_archive_without_path(blank_oscap_data):
    for line in ["content-url = http://example.com/oscap_content.tar",
                 "content-type = archive",
                 "profile = Web Server",
                 ]:
        blank_oscap_data.handle_line(line)

    with pytest.raises(KickstartValueError):
        blank_oscap_data.handle_end()


def test_unsupported_archive_type(blank_oscap_data):
    for line in ["content-url = http://example.com/oscap_content.tbz",
                 "content-type = archive",
                 "profile = Web Server",
                 "xccdf-path = xccdf.xml"
                 ]:
        blank_oscap_data.handle_line(line)

    with pytest.raises(KickstartValueError):
        blank_oscap_data.handle_end()


def test_enough_for_ds(blank_oscap_data):
    for line in ["content-url = http://example.com/test_ds.xml",
                 "content-type = datastream",
                 "profile = Web Server",
                 ]:
        blank_oscap_data.handle_line(line)

    blank_oscap_data.handle_end()


def test_enough_for_rpm(blank_oscap_data):
    for line in ["content-url = http://example.com/oscap_content.rpm",
                 "content-type = RPM",
                 "profile = Web Server",
                 "xccdf-path = /usr/share/oscap/xccdf.xml"
                 ]:
        blank_oscap_data.handle_line(line)

    blank_oscap_data.handle_end()


def test_enough_for_archive(blank_oscap_data):
    for line in ["content-url = http://example.com/oscap_content.tar",
                 "content-type = archive",
                 "profile = Web Server",
                 "xccdf-path = /usr/share/oscap/xccdf.xml"
                 ]:
        blank_oscap_data.handle_line(line)

    blank_oscap_data.handle_end()


def test_archive_preinst_content_path(blank_oscap_data):
    for line in ["content-url = http://example.com/oscap_content.tar",
                 "content-type = archive",
                 "profile = Web Server",
                 "xccdf-path = oscap/xccdf.xml"
                 ]:
        blank_oscap_data.handle_line(line)

    blank_oscap_data.handle_end()

    # content_name should be the archive's name
    assert blank_oscap_data.content_name == "oscap_content.tar"

    # content path should end with the xccdf path
    assert blank_oscap_data.preinst_content_path.endswith("oscap/xccdf.xml")


def test_ds_preinst_content_path(blank_oscap_data):
    for line in ["content-url = http://example.com/scap_content.xml",
                 "content-type = datastream",
                 "profile = Web Server",
                 ]:
        blank_oscap_data.handle_line(line)

    blank_oscap_data.handle_end()

    # both content_name and content path should point to the data stream
    # XML
    assert blank_oscap_data.content_name == "scap_content.xml"
    assert blank_oscap_data.preinst_content_path.endswith("scap_content.xml")


def test_archive_raw_content_paths(blank_oscap_data):
    for line in ["content-url = http://example.com/oscap_content.tar",
                 "content-type = archive",
                 "profile = Web Server",
                 "xccdf-path = oscap/xccdf.xml",
                 "tailoring-path = oscap/tailoring.xml",
                 ]:
        blank_oscap_data.handle_line(line)

    blank_oscap_data.handle_end()

    # content_name should be the archive's name
    assert blank_oscap_data.content_name == "oscap_content.tar"

    # content path should end with the archive's name
    assert blank_oscap_data.raw_preinst_content_path.endswith("oscap_content.tar")

    # tailoring paths should be returned properly
    assert (blank_oscap_data.preinst_tailoring_path
            == common.INSTALLATION_CONTENT_DIR + blank_oscap_data.policy_data.tailoring_path)

    assert (blank_oscap_data.postinst_tailoring_path
            == common.TARGET_CONTENT_DIR + blank_oscap_data.policy_data.tailoring_path)


def test_rpm_raw_content_paths(blank_oscap_data):
    for line in ["content-url = http://example.com/oscap_content.rpm",
                 "content-type = rpm",
                 "profile = Web Server",
                 "xccdf-path = /usr/share/oscap/xccdf.xml",
                 "tailoring-path = /usr/share/oscap/tailoring.xml",
                 ]:
        blank_oscap_data.handle_line(line)

    blank_oscap_data.handle_end()

    # content_name should be the rpm's name
    assert blank_oscap_data.content_name == "oscap_content.rpm"

    # content path should end with the rpm's name
    assert blank_oscap_data.raw_preinst_content_path.endswith("oscap_content.rpm")

    # content paths should be returned as expected
    assert (blank_oscap_data.preinst_content_path
            == os.path.normpath(common.INSTALLATION_CONTENT_DIR + blank_oscap_data.policy_data.content_path))

    # when using rpm, content_path doesn't change for the post-installation
    # phase
    assert blank_oscap_data.postinst_content_path == blank_oscap_data.policy_data.content_path


def test_ds_raw_content_paths(blank_oscap_data):
    for line in ["content-url = http://example.com/scap_content.xml",
                 "content-type = datastream",
                 "profile = Web Server",
                 ]:
        blank_oscap_data.handle_line(line)

    blank_oscap_data.handle_end()

    # content_name and content paths should all point to the data stream
    # XML
    assert blank_oscap_data.content_name == "scap_content.xml"
    assert blank_oscap_data.raw_preinst_content_path.endswith("scap_content.xml")


def test_valid_fingerprints(blank_oscap_data):
    for repetitions in (32, 40, 56, 64, 96, 128):
        blank_oscap_data.handle_line("fingerprint = %s" % ("a" * repetitions))


def test_invalid_fingerprints(blank_oscap_data):
    # invalid character
    with pytest.raises(KickstartValueError, match="Unsupported or invalid fingerprint"):
        blank_oscap_data.handle_line("fingerprint = %s?" % ("a" * 31))

    # invalid lengths (odd and even)
    for repetitions in (31, 41, 54, 66, 98, 124):
        with pytest.raises(
                KickstartValueError, match="Unsupported fingerprint"):
            blank_oscap_data.handle_line("fingerprint = %s" % ("a" * repetitions))
