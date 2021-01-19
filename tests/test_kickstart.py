#
# Copyright (C) 2021  Red Hat, Inc.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# the GNU General Public License v.2, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY expressed or implied, including the implied warranties of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License for more details.  You should have received a copy of the
# GNU General Public License along with this program; if not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.  Any Red Hat trademarks that are incorporated in the
# source code or documentation are not subject to the GNU General Public
# License and may only be used or replicated with the express permission of
# Red Hat, Inc.
#
import pytest
from textwrap import dedent
from org_fedora_oscap.service.oscap import OSCAPService


@pytest.fixture()
def service():
    return OSCAPService()


def check_ks_input(ks_service, ks_in, errors=None, warnings=None):
    """Read a provided kickstart string.

    :param ks_service: the kickstart service
    :param ks_in: a kickstart string
    :param errors: a list of expected errors
    :param warnings: a list of expected warning
    """
    errors = errors or []
    warnings = warnings or []
    report = ks_service.read_kickstart(ks_in)

    assert [i.message for i in report.error_messages] == errors
    assert [i.message for i in report.warning_messages] == warnings


def check_ks_output(ks_service, ks_out):
    """Generate a new kickstart string.

    :param ks_service: a kickstart service
    :param ks_out: an expected kickstart string
    """
    output = ks_service.generate_kickstart()
    assert output.strip() == dedent(ks_out).strip()


def test_default(service):
    check_ks_output(service, "")


def test_data(service):
    ks_in = """
    %addon org_fedora_oscap
        content-type = datastream
        content-url = "https://example.com/hardening.xml"
    %end
    """
    check_ks_input(service, ks_in)

    assert service.policy_data.content_type == "datastream"
    assert service.policy_data.content_url == "https://example.com/hardening.xml"


def test_datastream(service):
    ks_in = """
    %addon org_fedora_oscap
        content-type = datastream
        content-url = "https://example.com/hardening.xml"
        datastream-id = id_datastream_1
        xccdf-id = id_xccdf_new
        content-path = /usr/share/oscap/testing_ds.xml
        cpe-path = /usr/share/oscap/cpe.xml
        tailoring-path = /usr/share/oscap/tailoring.xml
        profile = "Web Server"
    %end
    """
    check_ks_input(service, ks_in)

    ks_out = """
    %addon org_fedora_oscap
        content-type = datastream
        content-url = https://example.com/hardening.xml
        datastream-id = id_datastream_1
        xccdf-id = id_xccdf_new
        content-path = /usr/share/oscap/testing_ds.xml
        cpe-path = /usr/share/oscap/cpe.xml
        tailoring-path = /usr/share/oscap/tailoring.xml
        profile = Web Server
    %end
    """
    check_ks_output(service, ks_out)


def test_no_content_type(service):
    ks_in = """
    %addon org_fedora_oscap
        content-url = http://example.com/test_ds.xml
        profile = Web Server
    %end
    """
    check_ks_input(service, ks_in, errors=[
        "content-type missing for the org_fedora_oscap addon"
    ])


def test_no_content_url(service):
    ks_in = """
    %addon org_fedora_oscap
        content-type = datastream
        profile = Web Server
    %end
    """
    check_ks_input(service, ks_in, errors=[
        "content-url missing for the org_fedora_oscap addon"
    ])


def test_no_profile(service):
    ks_in = """
    %addon org_fedora_oscap
        content-url = http://example.com/test_ds.xml
        content-type = datastream
    %end
    """
    check_ks_input(service, ks_in)

    ks_out = """
    %addon org_fedora_oscap
        content-type = datastream
        content-url = http://example.com/test_ds.xml
        profile = default
    %end
    """
    check_ks_output(service, ks_out)

    assert service.policy_data.profile_id == "default"


def test_rpm(service):
    ks_in = """
    %addon org_fedora_oscap
        content-url = http://example.com/oscap_content.rpm
        content-type = RPM
        profile = Web Server
        xccdf-path = /usr/share/oscap/xccdf.xml
    %end
    """
    check_ks_input(service, ks_in)

    ks_out = """
    %addon org_fedora_oscap
        content-type = rpm
        content-url = http://example.com/oscap_content.rpm
        content-path = /usr/share/oscap/xccdf.xml
        profile = Web Server
    %end
    """
    check_ks_output(service, ks_out)


def test_rpm_without_path(service):
    ks_in = """
    %addon org_fedora_oscap
        content-url = http://example.com/oscap_content.rpm
        content-type = RPM
        profile = Web Server
    %end
    """
    check_ks_input(service, ks_in, errors=[
        "Path to the XCCDF file has to be given if content in RPM or archive is used"
    ])


def test_rpm_with_wrong_suffix(service):
    ks_in = """
    %addon org_fedora_oscap
        content-url = http://example.com/oscap_content.xml
        content-type = RPM
        profile = Web Server
        xccdf-path = /usr/share/oscap/xccdf.xml
    %end
    """
    check_ks_input(service, ks_in, errors=[
        "Content type set to RPM, but the content URL doesn't end with '.rpm'"
    ])


def test_archive(service):
    ks_in = """
    %addon org_fedora_oscap
        content-url = http://example.com/oscap_content.tar
        content-type = archive
        profile = Web Server
        xccdf-path = oscap/xccdf.xml
    %end
    """
    check_ks_input(service, ks_in)

    ks_out = """
    %addon org_fedora_oscap
        content-type = archive
        content-url = http://example.com/oscap_content.tar
        content-path = oscap/xccdf.xml
        profile = Web Server
    %end
    """
    check_ks_output(service, ks_out)


def test_archive_without_path(service):
    ks_in = """
    %addon org_fedora_oscap
        content-url = http://example.com/oscap_content.tar
        content-type = archive
        profile = Web Server
    %end
    """
    check_ks_input(service, ks_in, errors=[
        "Path to the XCCDF file has to be given if content in RPM or archive is used"
    ])


def test_scap_security_guide(service):
    ks_in = """
    %addon org_fedora_oscap
        content-type = scap-security-guide
        profile = Web Server
    %end
    """
    check_ks_input(service, ks_in, errors=[
        "SCAP Security Guide not found on the system"
    ])


def test_fingerprints(service):
    ks_template = """
    %addon org_fedora_oscap
        content-url = http://example.com/test_ds.xml
        content-type = datastream
        fingerprint = {}
    %end
    """

    # invalid character
    ks_in = ks_template.format("a" * 31 + "?")
    check_ks_input(service, ks_in, errors=[
        "Unsupported or invalid fingerprint"
    ])

    # invalid lengths (odd and even)
    for repetitions in (31, 41, 54, 66, 98, 124):
        ks_in = ks_template.format("a" * repetitions)
        check_ks_input(service, ks_in, errors=[
            "Unsupported fingerprint"
        ])

    # valid values
    for repetitions in (32, 40, 56, 64, 96, 128):
        ks_in = ks_template.format("a" * repetitions)
        check_ks_input(service, ks_in)
