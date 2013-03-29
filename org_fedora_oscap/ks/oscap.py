#
# Copyright (C) 2013  Red Hat, Inc.
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
# Red Hat Author(s): Vratislav Podzimek <vpodzime@redhat.com>
#

"""Module with the OSCAPdata class."""

from pyanaconda.addons import AddonData
from pykickstart.errors import KickstartParseError, KickstartValueError

# export OSCAPdata class to prevent Anaconda's collect method from taking
# AddonData class instead of the OSCAPdata class
# @see: pyanaconda.kickstart.AnacondaKSHandler.__init__
__all__ = ["OSCAPdata"]

SUPPORTED_CONTENT_TYPES = ("datastream", "rpm",
                           # tarball?
                           )

SUPPORTED_URL_PREFIXES = ("http://", "https://",
                          # LABEL:?, hdaX:?,
                          )

class OSCAPdata(AddonData):
    """
    Class parsing and storing data for the OSCAP addon.

    @see: pyanaconda.addons.AddonData

    """

    def __init__(self, name):
        """
        @param name: name of the addon
        @type name: str

        """

        AddonData.__init__(self, name)
        self.content_type = ""
        self.content_url = ""
        self.datastream_id = ""
        self.xccdf_id = ""
        self.profile_id = ""

        # certificate to verify HTTPS connection or signed data
        self.certificate = ""

    def __str__(self):
        """
        What should end up between %addon and %end lines in the resulting
        kickstart file, i.e. string representation of the stored data.

        """

        def key_value_pair(key, value, ident=4):
            return "%s%s = %s" % (ident * " ", key, value)

        ret = "%%addon %s" % self.name
        ret += "\n%s" % key_value_pair("content-type", self.content_type)
        ret += "\n%s" % key_value_pair("content-url", self.content_url)

        if self.datastream_id:
            ret += "\n%s" % key_value_pair("datastream-id", self.datastream_id)
        if self.xccdf_id:
            ret += "\n%s" % key_value_pair("xccdf-id", self.xccdf_id)

        ret += "\n%s" % key_value_pair("profile", self.profile_id)

        if self.certificate:
            ret += "\n%s" % key_value_pair("certificate", self.certificate)

        ret += "\n%end"
        return ret

    def _parse_content_type(self, value):
        if value in SUPPORTED_CONTENT_TYPES:
            self.content_type = value
        else:
            msg = "Unsupported content type '%s' in the %s addon" % (value,
                                                                     self.name)
            raise KickstartValueError(msg)

    def _parse_content_url(self, value):
        if any(value.startswith(prefix)
               for prefix in SUPPORTED_URL_PREFIXES):
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

    def handle_line(self, line):
        """
        The handle_line method that is called with every line from this addon's
        %addon section of the kickstart file.

        @param line: a single line from the %addon section
        @type line: str

        """

        actions = { "content-type" : self._parse_content_type,
                    "content-url" : self._parse_content_url,
                    "datastream-id" : self._parse_datastream_id,
                    "profile" : self._parse_profile_id,
                    "xccdf-id" : self._parse_xccdf_id,
                    }

        line = line.strip()
        (pre, sep, post) = line.partition("=")

        try:
            actions[pre.strip()](post.strip())
        except KeyError:
            msg = "Unknown item '%s' for %s addon" % (line, self.name)
            raise KickstartParseError(msg)

    def finalize(self):
        tmpl = "%s missing for the %s addon"

        if not self.content_type:
            raise KickstartValueError(tmpl % ("content-type", self.name))

        if not self.content_url:
            raise KickstartValueError(tmpl % ("content-url", self.name))

        if self.content_type == "datastream":
            if not self.datastream_id:
                raise KickstartValueError(tmpl % ("datastream-id", self.name))
            if not self.xccdf_id:
                raise KickstartValueError(tmpl % ("xccdf-id", self.name))

        if not self.profile_id:
            raise KickstartValueError(tmpl % ("profile", self.name))

    def setup(self, storage, ksdata, instclass):
        """
        The setup method that should make changes to the runtime environment
        according to the data stored in this object.

        @param storage: object storing storage-related information
                        (disks, partitioning, bootloader, etc.)
        @type storage: blivet.Blivet instance
        @param ksdata: data parsed from the kickstart file and set in the
                       installation process
        @type ksdata: pykickstart.base.BaseHandler instance
        @param instclass: distribution-specific information
        @type instclass: pyanaconda.installclass.BaseInstallClass

        """

        # add packages needed on the target system to the list of packages
        # that are requested to be installed
        for pkg in ("oscap", "oscap-utils"):
            if pkg not in ksdata.packages.packageList:
                ksdata.packages.packageList.append(pkg)

    def execute(self, storage, ksdata, instclass, users):
        """
        The execute method that should make changes to the installed system. It
        is called only once in the post-install setup phase.

        @see: setup
        @param users: information about created users
        @type users: pyanaconda.users.Users instance

        """

        #TODO: call oscap remediate in chroot
        pass

if __name__ == "__main__":
    addon_data = OSCAPdata("org_fedora_oscap")

    for line in ["content-type = datastream\n",
                 "content-url = https://example.com/hardening.xml\n",
                 "datastream-id = id_datastream_1\n",
                 "xccdf-id = id_xccdf_new\n",
                 "profile = Web Server\n",
                 ]:
        addon_data.handle_line(line)

    addon_data.finalize()

    addon_data_str = str(addon_data)

    print "====__str__ test===="
    print addon_data_str
    print

    addon_data2 = OSCAPdata("org_fedora_oscap")
    for line in addon_data_str.split("\n")[1:-1]:
        addon_data2.handle_line(line)
    addon_data2.finalize()

    print "====__str__ value parsed===="
    print str(addon_data2)


