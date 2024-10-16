#
# Copyright (C) 2020 Red Hat, Inc.
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
import logging
import re

from pyanaconda.core.kickstart import KickstartSpecification
from pyanaconda.core.kickstart.addon import AddonData
from pykickstart.errors import KickstartValueError, KickstartParseError

from org_fedora_oscap import common, utils
from org_fedora_oscap.structures import PolicyData

log = logging.getLogger("anaconda")

__all__ = ["OSCAPKickstartSpecification"]


FINGERPRINT_REGEX = re.compile(r'^[a-z0-9]+$')


def key_value_pair(key, value, indent=4):
    return "%s%s = %s" % (indent * " ", key, value)


class AdditionalPropertiesMixin:
    @property
    def content_name(self) -> str:
        return common.get_content_name(self.policy_data)

    @property
    def preinst_content_path(self) -> str:
        return common.get_preinst_content_path(self.policy_data)

    @property
    def preinst_tailoring_path(self) -> str:
        return common.get_preinst_tailoring_path(self.policy_data)

    @property
    def postinst_content_path(self) -> str:
        return common.get_postinst_content_path(self.policy_data)

    @property
    def postinst_tailoring_path(self) -> str:
        return common.get_postinst_tailoring_path(self.policy_data)

    @property
    def raw_preinst_content_path(self) -> str:
        return common.get_raw_preinst_content_path(self.policy_data)


class OSCAPKickstartData(AddonData, AdditionalPropertiesMixin):
    """The kickstart data for the add-on."""

    def __init__(self):
        super().__init__()
        self.policy_data = PolicyData()

        """The name of the %addon section."""
        self.name = common.ADDON_NAMES[0]
        self.addon_section_present = False

    def handle_header(self, args, line_number=None):
        """Handle the arguments of the %addon line.

        :param args: a list of additional arguments
        :param line_number: a line number
        :raise: KickstartParseError for invalid arguments
        """
        self.addon_section_present = True

    def handle_line(self, line, line_number=None):
        """Handle one line of the section.

        :param line: a line to parse
        :param line_number: a line number
        :raise: KickstartParseError for invalid lines
        """
        actions = {
            "content-type": self._parse_content_type,
            "content-url": self._parse_content_url,
            "content-path": self._parse_content_path,
            "datastream-id": self._parse_datastream_id,
            "profile": self._parse_profile_id,
            "xccdf-id": self._parse_xccdf_id,
            "xccdf-path": self._parse_content_path,
            "cpe-path": self._parse_cpe_path,
            "tailoring-path": self._parse_tailoring_path,
            "fingerprint": self._parse_fingerprint,
            "certificates": self._parse_certificates,
            "remediate": self._parse_remediate,
        }

        line = line.strip()
        (pre, sep, post) = line.partition("=")
        pre = pre.strip()
        post = post.strip()
        post = post.strip('"')

        try:
            actions[pre](post)
        except KeyError:
            msg = "Unknown item '%s' for %s addon" % (line, self.name)
            raise KickstartParseError(msg)

    def _parse_content_type(self, value):
        value_low = value.lower()
        if value_low in common.SUPPORTED_CONTENT_TYPES:
            self.policy_data.content_type = value_low
        else:
            msg = "Unsupported content type '%s' in the %s addon" % (value,
                                                                     self.name)
            raise KickstartValueError(msg)

    def _parse_content_url(self, value):
        if any(value.startswith(prefix)
               for prefix in common.SUPPORTED_URL_PREFIXES):
            self.policy_data.content_url = value
        else:
            msg = "Unsupported url '%s' in the %s addon" % (value, self.name)
            raise KickstartValueError(msg)

    def _parse_datastream_id(self, value):
        # need to be checked?
        self.policy_data.datastream_id = value

    def _parse_xccdf_id(self, value):
        # need to be checked?
        self.policy_data.xccdf_id = value

    def _parse_profile_id(self, value):
        # need to be checked?
        self.policy_data.profile_id = value

    def _parse_content_path(self, value):
        # need to be checked?
        self.policy_data.content_path = value

    def _parse_cpe_path(self, value):
        # need to be checked?
        self.policy_data.cpe_path = value

    def _parse_tailoring_path(self, value):
        # need to be checked?
        self.policy_data.tailoring_path = value

    def _parse_fingerprint(self, value):
        if FINGERPRINT_REGEX.match(value) is None:
            msg = "Unsupported or invalid fingerprint"
            raise KickstartValueError(msg)

        if utils.get_hashing_algorithm(value) is None:
            msg = "Unsupported fingerprint"
            raise KickstartValueError(msg)

        self.policy_data.fingerprint = value

    def _parse_certificates(self, value):
        self.policy_data.certificates = value

    def _parse_remediate(self, value):
        assert value in ("none", "post", "firstboot", "both")
        self.policy_data.remediate = value

    def handle_end(self):
        """Handle the end of the section."""
        tmpl = "%s missing for the %s addon"

        # check provided data
        if not self.policy_data.content_type:
            raise KickstartValueError(tmpl % ("content-type", self.name))

        if (
                self.policy_data.content_type != "scap-security-guide"
                and not self.policy_data.content_url):
            raise KickstartValueError(tmpl % ("content-url", self.name))

        if not self.policy_data.profile_id:
            self.policy_data.profile_id = "default"

        if (
                self.policy_data.content_type in ("rpm", "archive")
                and not self.policy_data.content_path):
            msg = "Path to the XCCDF file has to be given if content in RPM "\
                  "or archive is used"
            raise KickstartValueError(msg)

        if (
                self.policy_data.content_type == "rpm"
                and not self.policy_data.content_url.endswith(".rpm")):
            msg = "Content type set to RPM, but the content URL doesn't end "\
                  "with '.rpm'"
            raise KickstartValueError(msg)

        if self.policy_data.content_type == "archive":
            supported_archive = any(
                self.policy_data.content_url.endswith(arch_type)
                for arch_type in common.SUPPORTED_ARCHIVES
            )
            if not supported_archive:
                msg = "Unsupported archive type of the content "\
                      "file '%s'" % self.policy_data.content_url
                raise KickstartValueError(msg)

        # do some initialization magic in case of SSG
        if self.policy_data.content_type == "scap-security-guide":
            if not common.ssg_available():
                msg = "SCAP Security Guide not found on the system"
                raise KickstartValueError(msg)

            self.policy_data.content_path = common.SSG_DIR + common.SSG_CONTENT

    def __str__(self):
        """Generate the kickstart representation.

        What should end up in the resulting kickstart file,
        i.e. string representation of the stored data.

        :return: a string
        """
        if not self.policy_data.profile_id:
            return ""

        ret = "%%addon %s" % self.name
        ret += "\n%s" % key_value_pair("content-type", self.policy_data.content_type)

        if self.policy_data.content_url:
            ret += "\n%s" % key_value_pair("content-url", self.policy_data.content_url)

        if self.policy_data.datastream_id:
            ret += "\n%s" % key_value_pair("datastream-id", self.policy_data.datastream_id)

        if self.policy_data.xccdf_id:
            ret += "\n%s" % key_value_pair("xccdf-id", self.policy_data.xccdf_id)

        if (
                self.policy_data.content_path
                and self.policy_data.content_type != "scap-security-guide"):
            ret += "\n%s" % key_value_pair("content-path", self.policy_data.content_path)

        if self.policy_data.cpe_path:
            ret += "\n%s" % key_value_pair("cpe-path", self.policy_data.cpe_path)

        if self.policy_data.tailoring_path:
            ret += "\n%s" % key_value_pair("tailoring-path", self.policy_data.tailoring_path)

        ret += "\n%s" % key_value_pair("profile", self.policy_data.profile_id)

        if self.policy_data.fingerprint:
            ret += "\n%s" % key_value_pair("fingerprint", self.policy_data.fingerprint)

        if self.policy_data.certificates:
            ret += "\n%s" % key_value_pair("certificates", self.policy_data.certificates)

        if self.policy_data.remediate:
            ret += "\n%s" % key_value_pair("remediate", self.policy_data.remediate)

        ret += "\n%end\n\n"
        return ret


def get_oscap_kickstart_data(name):
    class NamedOSCAPKickstartData(OSCAPKickstartData):
        def __init__(self):
            super().__init__()
            self.name = name

    return NamedOSCAPKickstartData


class OSCAPKickstartSpecification(KickstartSpecification):
    """The kickstart specification of the OSCAP service."""

    addons = {
        name: get_oscap_kickstart_data(name) for name in common.ADDON_NAMES
    }
