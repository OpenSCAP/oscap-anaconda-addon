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

import shutil
import re
import os
import time
import logging
import gettext

from pyanaconda.addons import AddonData
from pyanaconda.iutil import getSysroot
from pyanaconda.progress import progressQ
from pyanaconda import errors
from pyanaconda import iutil
from pyanaconda import flags
from pykickstart.errors import KickstartParseError, KickstartValueError
from org_fedora_oscap import utils, common, rule_handling, data_fetch
from org_fedora_oscap.common import SUPPORTED_ARCHIVES
from org_fedora_oscap.content_handling import ContentCheckError

log = logging.getLogger("anaconda")

_ = lambda x: gettext.ldgettext("oscap-anaconda-addon", x)

# export OSCAPdata class to prevent Anaconda's collect method from taking
# AddonData class instead of the OSCAPdata class
# @see: pyanaconda.kickstart.AnacondaKSHandler.__init__
__all__ = ["OSCAPdata"]

SUPPORTED_CONTENT_TYPES = ("datastream", "rpm", "archive",
                           "scap-security-guide",
                           )

SUPPORTED_URL_PREFIXES = ("http://", "https://", "ftp://"
                          # LABEL:?, hdaX:?,
                          )

REQUIRED_PACKAGES = ("openscap", "openscap-scanner", )

FINGERPRINT_REGEX = re.compile(r'^[a-z0-9]+$')


class MisconfigurationError(common.OSCAPaddonError):
    """Exception for reporting misconfiguration."""

    pass


class OSCAPdata(AddonData):
    """
    Class parsing and storing data for the OSCAP addon.

    :see: pyanaconda.addons.AddonData

    """

    def __init__(self, name, just_clear=False):
        """
        :param name: name of the addon
        :type name: str

        """

        if not just_clear:
            # do not call the parent's __init__ more than once
            AddonData.__init__(self, name)

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

        # internal values
        self.rule_data = rule_handling.RuleData()
        self.dry_run = False

    def __str__(self):
        """
        What should end up in the resulting kickstart file, i.e. string
        representation of the stored data.

        """

        if self.dry_run or not self.profile_id:
            # the addon was run in the dry run mode, omit it from the kickstart
            return ""

        def key_value_pair(key, value, indent=4):
            return "%s%s = %s" % (indent * " ", key, value)

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
            ret += "\n%s" % key_value_pair("tailoring-path",
                                           self.tailoring_path)

        ret += "\n%s" % key_value_pair("profile", self.profile_id)

        if self.fingerprint:
            ret += "\n%s" % key_value_pair("fingerprint", self.fingerprint)

        if self.certificates:
            ret += "\n%s" % key_value_pair("certificates", self.certificates)

        ret += "\n%end\n\n"
        return ret

    def _parse_content_type(self, value):
        value_low = value.lower()
        if value_low in SUPPORTED_CONTENT_TYPES:
            self.content_type = value_low
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

    def handle_line(self, line):
        """
        The handle_line method that is called with every line from this addon's
        %addon section of the kickstart file.

        :param line: a single line from the %addon section
        :type line: str

        """

        actions = {"content-type": self._parse_content_type,
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

    def finalize(self):
        """
        The finalize method that is called when the end of the %addon section
        (the %end line) is reached. It means no more kickstart data will come.

        """

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
            supported_archive = any(self.content_url.endswith(arch_type)
                                    for arch_type in SUPPORTED_ARCHIVES)
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

    @property
    def content_defined(self):
        return self.content_url or self.content_type == "scap-security-guide"

    @property
    def content_name(self):
        if self.content_type == "scap-security-guide":
            raise ValueError("Using scap-security-guide, no single content file")

        rest = "/anonymous_content"
        for prefix in SUPPORTED_URL_PREFIXES:
            if self.content_url.startswith(prefix):
                rest = self.content_url[len(prefix):]
                break

        parts = rest.rsplit("/", 1)
        if len(parts) != 2:
            msg = "Unsupported url '%s' in the %s addon" % (self.content_url,
                                                            self.name)
            raise KickstartValueError(msg)

        return parts[1]

    @property
    def raw_preinst_content_path(self):
        """Path to the raw (unextracted, ...) pre-installation content file"""

        return utils.join_paths(common.INSTALLATION_CONTENT_DIR,
                                self.content_name)

    @property
    def raw_postinst_content_path(self):
        """Path to the raw (unextracted, ...) post-installation content file"""

        return utils.join_paths(common.TARGET_CONTENT_DIR,
                                self.content_name)

    @property
    def preinst_content_path(self):
        """Path to the pre-installation content file"""

        if self.content_type == "datastream":
            return utils.join_paths(common.INSTALLATION_CONTENT_DIR,
                                    self.content_name)
        elif self.content_type == "scap-security-guide":
            # SSG is not copied to the standard place
            return self.content_path
        else:
            return utils.join_paths(common.INSTALLATION_CONTENT_DIR,
                                    self.content_path)

    @property
    def postinst_content_path(self):
        """Path to the post-installation content file"""

        if self.content_type == "datastream":
            return utils.join_paths(common.TARGET_CONTENT_DIR,
                                    self.content_name)
        elif self.content_type in ("rpm", "scap-security-guide"):
            # no path magic in case of RPM (SSG is installed as an RPM)
            return self.content_path
        else:
            return utils.join_paths(common.TARGET_CONTENT_DIR,
                                    self.content_path)

    @property
    def preinst_tailoring_path(self):
        """Path to the pre-installation tailoring file (if any)"""

        if not self.tailoring_path:
            return ""

        return utils.join_paths(common.INSTALLATION_CONTENT_DIR,
                                self.tailoring_path)

    @property
    def postinst_tailoring_path(self):
        """Path to the post-installation tailoring file (if any)"""

        if not self.tailoring_path:
            return ""

        if self.content_type == "rpm":
            # no path magic in case of RPM
            return self.tailoring_path

        return utils.join_paths(common.TARGET_CONTENT_DIR,
                                self.tailoring_path)

    def _fetch_content_and_initialize(self):
        """Fetch content and initialize from it"""

        data_fetch.fetch_data(self.content_url, self.raw_preinst_content_path,
                              self.certificates)
        # RPM is an archive at this phase
        if self.content_type in ("archive", "rpm"):
            # extract the content
            common.extract_data(self.raw_preinst_content_path,
                                common.INSTALLATION_CONTENT_DIR,
                                [self.content_path])

        rules = common.get_fix_rules_pre(self.profile_id,
                                         self.preinst_content_path,
                                         self.datastream_id, self.xccdf_id,
                                         self.preinst_tailoring_path)

        # parse and store rules with a clean RuleData instance
        self.rule_data = rule_handling.RuleData()
        for rule in rules.splitlines():
            self.rule_data.new_rule(rule)

    def setup(self, storage, ksdata, instclass, payload):
        """
        The setup method that should make changes to the runtime environment
        according to the data stored in this object.

        :param storage: object storing storage-related information
                        (disks, partitioning, bootloader, etc.)
        :type storage: blivet.Blivet instance
        :param ksdata: data parsed from the kickstart file and set in the
                       installation process
        :type ksdata: pykickstart.base.BaseHandler instance
        :param instclass: distribution-specific information
        :type instclass: pyanaconda.installclass.BaseInstallClass

        """

        if self.dry_run or not self.profile_id:
            # nothing more to be done in the dry-run mode or if no profile is
            # selected
            return

        if not os.path.exists(self.preinst_content_path) and not os.path.exists(self.raw_preinst_content_path):
            # content not available/fetched yet
            try:
                self._fetch_content_and_initialize()
            except (common.OSCAPaddonError, data_fetch.DataFetchError) as e:
                log.error("Failed to fetch and initialize SCAP content!")
                msg = _("There was an error fetching and loading the security content:\n" +
                        "%s\n" +
                        "The installation should be aborted. Do you wish to continue anyway?") % e

                if flags.flags.automatedInstall and not flags.flags.ksprompt:
                    # cannot have ask in a non-interactive kickstart
                    # installation
                    raise errors.CmdlineError(msg)

                answ = errors.errorHandler.ui.showYesNoQuestion(msg)
                if answ == errors.ERROR_CONTINUE:
                    # prevent any futher actions here by switching to the dry
                    # run mode and let things go on
                    self.dry_run = True
                    return
                else:
                    # Let's sleep forever to prevent any further actions and
                    # wait for the main thread to quit the process.
                    progressQ.send_quit(1)
                    while True:
                        time.sleep(100000)

        # check fingerprint if given
        if self.fingerprint:
            hash_obj = utils.get_hashing_algorithm(self.fingerprint)
            digest = utils.get_file_fingerprint(self.raw_preinst_content_path,
                                                hash_obj)
            if digest != self.fingerprint:
                log.error("Failed to fetch and initialize SCAP content!")
                msg = _("The integrity check of the security content failed.\n" +
                        "The installation should be aborted. Do you wish to continue anyway?")

                if flags.flags.automatedInstall and not flags.flags.ksprompt:
                    # cannot have ask in a non-interactive kickstart
                    # installation
                    raise errors.CmdlineError(msg)

                answ = errors.errorHandler.ui.showYesNoQuestion(msg)
                if answ == errors.ERROR_CONTINUE:
                    # prevent any futher actions here by switching to the dry
                    # run mode and let things go on
                    self.dry_run = True
                    return
                else:
                    # Let's sleep forever to prevent any further actions and
                    # wait for the main thread to quit the process.
                    progressQ.send_quit(1)
                    while True:
                        time.sleep(100000)

        # evaluate rules, do automatic fixes and stop if something that cannot
        # be fixed automatically is wrong
        fatal_messages = [message for message in self.rule_data.eval_rules(ksdata, storage)
                          if message.type == common.MESSAGE_TYPE_FATAL]
        if any(fatal_messages):
            msg = "Wrong configuration detected!\n"
            msg += "\n".join(message.text for message in fatal_messages)
            msg += "\nThe installation should be aborted. Do you wish to continue anyway?"
            if flags.flags.automatedInstall and not flags.flags.ksprompt:
                # cannot have ask in a non-interactive kickstart installation
                raise errors.CmdlineError(msg)

            answ = errors.errorHandler.ui.showYesNoQuestion(msg)
            if answ == errors.ERROR_CONTINUE:
                # prevent any futher actions here by switching to the dry
                # run mode and let things go on
                self.dry_run = True
                return
            else:
                # Let's sleep forever to prevent any further actions and wait
                # for the main thread to quit the process.
                progressQ.send_quit(1)
                while True:
                    time.sleep(100000)

        # add packages needed on the target system to the list of packages
        # that are requested to be installed
        pkgs_to_install = list(REQUIRED_PACKAGES)
        if self.content_type == "scap-security-guide":
            pkgs_to_install.append("scap-security-guide")
        for pkg in pkgs_to_install:
            if pkg not in ksdata.packages.packageList:
                ksdata.packages.packageList.append(pkg)

    def execute(self, storage, ksdata, instclass, users, payload):
        """
        The execute method that should make changes to the installed system. It
        is called only once in the post-install setup phase.

        :see: setup
        :param users: information about created users
        :type users: pyanaconda.users.Users instance

        """

        if self.dry_run or not self.profile_id:
            # nothing more to be done in the dry-run mode or if no profile is
            # selected
            return

        target_content_dir = utils.join_paths(getSysroot(),
                                              common.TARGET_CONTENT_DIR)
        utils.ensure_dir_exists(target_content_dir)

        if self.content_type == "datastream":
            shutil.copy2(self.preinst_content_path, target_content_dir)
        elif self.content_type == "rpm":
            # copy the RPM to the target system
            shutil.copy2(self.raw_preinst_content_path, target_content_dir)

            # and install it with yum
            ret = iutil.execInSysroot("yum", ["-y", "--nogpg", "install",
                                              self.raw_postinst_content_path])
            if ret != 0:
                raise common.ExtractionError("Failed to install content "
                                             "RPM to the target system")
        elif self.content_type == "scap-security-guide":
            # nothing needed
            pass
        else:
            utils.universal_copy(utils.join_paths(common.INSTALLATION_CONTENT_DIR,
                                                  "*"),
                                 target_content_dir)
        if os.path.exists(self.preinst_tailoring_path):
            shutil.copy2(self.preinst_tailoring_path, target_content_dir)

        common.run_oscap_remediate(self.profile_id, self.postinst_content_path,
                                   self.datastream_id, self.xccdf_id,
                                   self.postinst_tailoring_path,
                                   chroot=getSysroot())

    def clear_all(self):
        """Clear all the stored values."""

        self.__init__(self.name, just_clear=True)
