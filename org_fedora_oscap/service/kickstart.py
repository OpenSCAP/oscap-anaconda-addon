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

log = logging.getLogger(__name__)

__all__ = ["OSCAPKickstartSpecification"]


FINGERPRINT_REGEX = re.compile(r'^[a-z0-9]+$')


def key_value_pair(key, value, indent=4):
    return "%s%s = %s" % (indent * " ", key, value)


class OSCAPKickstartData(AddonData):
    """The kickstart data for the org_fedora_oscap add-on."""

    def __init__(self):
        super().__init__()
        # values specifying the content
        self.content_type = ""
        self.content_url = ""
        self.datastream_id = ""
        self.xccdf_id = ""
        self.profile_id = ""
        self.content_path = ""
        self.cpe_path = ""
        self.tailoring_path = ""

        # additional values
        self.fingerprint = ""

        # certificate to verify HTTPS connection or signed data
        self.certificates = ""

    @property
    def name(self):
        """The name of the %addon section."""
        return "org_fedora_oscap"

    def handle_header(self, args, line_number=None):
        """Handle the arguments of the %addon line.

        :param args: a list of additional arguments
        :param line_number: a line number
        :raise: KickstartParseError for invalid arguments
        """
        pass

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
            self.content_type = value_low
        else:
            msg = "Unsupported content type '%s' in the %s addon" % (value,
                                                                     self.name)
            raise KickstartValueError(msg)

    def _parse_content_url(self, value):
        if any(value.startswith(prefix)
               for prefix in common.SUPPORTED_URL_PREFIXES):
            self.content_url = value
        else:
            msg = "Unsupported url '%s' in the %s addon" % (value, self.name)
            raise KickstartValueError(msg)

    def _parse_datastream_id(self, value):
        # need to be checked?
        self.datastream_id = value

    def _parse_xccdf_id(self, value):
        # need to be checked?
        self.xccdf_id = value

    def _parse_profile_id(self, value):
        # need to be checked?
        self.profile_id = value

    def _parse_content_path(self, value):
        # need to be checked?
        self.content_path = value

    def _parse_cpe_path(self, value):
        # need to be checked?
        self.cpe_path = value

    def _parse_tailoring_path(self, value):
        # need to be checked?
        self.tailoring_path = value

    def _parse_fingerprint(self, value):
        if FINGERPRINT_REGEX.match(value) is None:
            msg = "Unsupported or invalid fingerprint"
            raise KickstartValueError(msg)

        if utils.get_hashing_algorithm(value) is None:
            msg = "Unsupported fingerprint"
            raise KickstartValueError(msg)

        self.fingerprint = value

    def _parse_certificates(self, value):
        self.certificates = value

    def handle_end(self):
        """Handle the end of the section."""
        tmpl = "%s missing for the %s addon"

        # check provided data
        if not self.content_type:
            raise KickstartValueError(tmpl % ("content-type", self.name))

        if self.content_type != "scap-security-guide" and not self.content_url:
            raise KickstartValueError(tmpl % ("content-url", self.name))

        if not self.profile_id:
            self.profile_id = "default"

        if self.content_type in ("rpm", "archive") and not self.content_path:
            msg = "Path to the XCCDF file has to be given if content in RPM "\
                  "or archive is used"
            raise KickstartValueError(msg)

        if self.content_type == "rpm" and not self.content_url.endswith(".rpm"):
            msg = "Content type set to RPM, but the content URL doesn't end "\
                  "with '.rpm'"
            raise KickstartValueError(msg)

        if self.content_type == "archive":
            supported_archive = any(
                self.content_url.endswith(arch_type)
                for arch_type in common.SUPPORTED_ARCHIVES
            )
            if not supported_archive:
                msg = "Unsupported archive type of the content "\
                      "file '%s'" % self.content_url
                raise KickstartValueError(msg)

        # do some initialization magic in case of SSG
        if self.content_type == "scap-security-guide":
            if not common.ssg_available():
                msg = "SCAP Security Guide not found on the system"
                raise KickstartValueError(msg)

            self.content_path = common.SSG_DIR + common.SSG_CONTENT

    def __str__(self):
        """Generate the kickstart representation.

        What should end up in the resulting kickstart file,
        i.e. string representation of the stored data.

        :return: a string
        """
        if not self.profile_id:
            return ""

        ret = "%%addon %s" % self.name
        ret += "\n%s" % key_value_pair("content-type", self.content_type)

        if self.content_url:
            ret += "\n%s" % key_value_pair("content-url", self.content_url)

        if self.datastream_id:
            ret += "\n%s" % key_value_pair("datastream-id", self.datastream_id)

        if self.xccdf_id:
            ret += "\n%s" % key_value_pair("xccdf-id", self.xccdf_id)

        if self.content_path and self.content_type != "scap-security-guide":
            ret += "\n%s" % key_value_pair("content-path", self.content_path)

        if self.cpe_path:
            ret += "\n%s" % key_value_pair("cpe-path", self.cpe_path)

        if self.tailoring_path:
            ret += "\n%s" % key_value_pair("tailoring-path", self.tailoring_path)

        ret += "\n%s" % key_value_pair("profile", self.profile_id)

        if self.fingerprint:
            ret += "\n%s" % key_value_pair("fingerprint", self.fingerprint)

        if self.certificates:
            ret += "\n%s" % key_value_pair("certificates", self.certificates)

        ret += "\n%end\n\n"
        return ret


class OSCAPKickstartSpecification(KickstartSpecification):
    """The kickstart specification of the OSCAP service."""

    addons = {
        "org_fedora_oscap": OSCAPKickstartData
    }
