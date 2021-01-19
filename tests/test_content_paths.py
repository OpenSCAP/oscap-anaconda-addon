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

from org_fedora_oscap.structures import PolicyData
from org_fedora_oscap import common


def test_datastream_content_paths():
    data = PolicyData()
    data.content_type = "datastream"
    data.content_url = "https://example.com/hardening.xml"
    data.datastream_id = "id_datastream_1"
    data.xccdf_id = "id_xccdf_new"
    data.content_path = "/usr/share/oscap/testing_ds.xml"
    data.cpe_path = "/usr/share/oscap/cpe.xml"
    data.tailoring_path = "/usr/share/oscap/tailoring.xml"
    data.profile_id = "Web Server"

    assert common.get_content_name(data) == "hardening.xml"

    expected_path = "/tmp/openscap_data/hardening.xml"
    assert common.get_raw_preinst_content_path(data) == expected_path

    expected_path = "/tmp/openscap_data/hardening.xml"
    assert common.get_preinst_content_path(data) == expected_path

    expected_path = "/root/openscap_data/hardening.xml"
    assert common.get_postinst_content_path(data) == expected_path

    expected_path = "/tmp/openscap_data/usr/share/oscap/tailoring.xml"
    assert common.get_preinst_tailoring_path(data) == expected_path

    expected_path = "/root/openscap_data/usr/share/oscap/tailoring.xml"
    assert common.get_postinst_tailoring_path(data) == expected_path


def test_archive_content_paths():
    data = PolicyData()
    data.content_type = "archive"
    data.content_url = "http://example.com/oscap_content.tar"
    data.content_path = "oscap/xccdf.xml"
    data.profile_id = "Web Server"
    data.content_path = "oscap/xccdf.xml"
    data.tailoring_path = "oscap/tailoring.xml"

    assert common.get_content_name(data) == "oscap_content.tar"

    expected_path = "/tmp/openscap_data/oscap_content.tar"
    assert common.get_raw_preinst_content_path(data) == expected_path

    expected_path = "/tmp/openscap_data/oscap/xccdf.xml"
    assert common.get_preinst_content_path(data) == expected_path

    expected_path = "/root/openscap_data/oscap/xccdf.xml"
    assert common.get_postinst_content_path(data) == expected_path

    expected_path = "/tmp/openscap_data/oscap/tailoring.xml"
    assert common.get_preinst_tailoring_path(data) == expected_path

    expected_path = "/root/openscap_data/oscap/tailoring.xml"
    assert common.get_postinst_tailoring_path(data) == expected_path


def test_rpm_content_paths():
    data = PolicyData()
    data.content_type = "rpm"
    data.content_url = "http://example.com/oscap_content.rpm"
    data.profile_id = "Web Server"
    data.content_path = "/usr/share/oscap/xccdf.xml"
    data.tailoring_path = "/usr/share/oscap/tailoring.xml"

    assert common.get_content_name(data) == "oscap_content.rpm"

    expected_path = "/tmp/openscap_data/oscap_content.rpm"
    assert common.get_raw_preinst_content_path(data) == expected_path

    expected_path = "/tmp/openscap_data/usr/share/oscap/xccdf.xml"
    assert common.get_preinst_content_path(data) == expected_path

    expected_path = "/usr/share/oscap/xccdf.xml"
    assert common.get_postinst_content_path(data) == expected_path

    expected_path = "/tmp/openscap_data/usr/share/oscap/tailoring.xml"
    assert common.get_preinst_tailoring_path(data) == expected_path

    expected_path = "/usr/share/oscap/tailoring.xml"
    assert common.get_postinst_tailoring_path(data) == expected_path


def test_scap_security_guide_paths():
    data = PolicyData()
    data.content_type = "scap-security-guide"
    data.profile_id = "Web Server"
    data.content_path = "/usr/share/xml/scap/ssg/content.xml"

    expected_msg = "Using scap-security-guide, no single content file"
    with pytest.raises(ValueError, match=expected_msg):
        common.get_content_name(data)

    expected_path = None
    assert common.get_raw_preinst_content_path(data) == expected_path

    expected_path = "/usr/share/xml/scap/ssg/content.xml"
    assert common.get_preinst_content_path(data) == expected_path

    expected_path = "/usr/share/xml/scap/ssg/content.xml"
    assert common.get_postinst_content_path(data) == expected_path

    expected_path = ""
    assert common.get_preinst_tailoring_path(data) == expected_path

    expected_path = ""
    assert common.get_postinst_tailoring_path(data) == expected_path
