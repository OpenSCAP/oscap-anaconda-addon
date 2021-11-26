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
import os
import shutil

from pyanaconda.core import util
from pyanaconda.modules.common.task import Task
from pyanaconda.modules.common.errors.installation import NonCriticalInstallationError

from org_fedora_oscap import common, data_fetch, rule_handling, utils
from org_fedora_oscap.common import _, get_packages_data, set_packages_data
from org_fedora_oscap.content_handling import ContentCheckError
from org_fedora_oscap import content_discovery

log = logging.getLogger("anaconda")


REQUIRED_PACKAGES = ("openscap", "openscap-scanner",)


def _handle_error(exception):
    log.error("OSCAP Addon: Failed to fetch and initialize SCAP content!")

    if isinstance(exception, ContentCheckError):
        msg = _("The integrity check of the security content failed.")
        terminate(msg)
    elif (
            isinstance(exception, common.OSCAPaddonError)
            or isinstance(exception, data_fetch.DataFetchError)):
        msg = _("There was an error fetching and loading the security content:\n" +
                f"{str(exception)}")
        terminate(msg)

    else:
        msg = _("There was an unexpected problem with the supplied content.")
        terminate(msg)


def terminate(message):
    message += "\n" + _("The installation should be aborted.")
    raise NonCriticalInstallationError(message)


class PrepareValidContent(Task):
    """The installation task for fetching the content."""

    def __init__(self, policy_data, file_path, content_path):
        """Create a task."""
        super().__init__()
        self._policy_data = policy_data
        self._file_path = file_path
        self._content_path = content_path
        self.content_bringer = content_discovery.ContentBringer(policy_data)

    @property
    def name(self):
        return "Fetch the content, and optionally perform check or archive extraction"

    def run(self):
        """Run the task."""
        # Is the content available?
        fetching_thread_name = None
        if not os.path.exists(self._content_path):
            # content not available/fetched yet
            fetching_thread_name = self.content_bringer.fetch_content(
                _handle_error, self._policy_data.certificates)

        content_dest = None
        if self._policy_data.content_type != "scap-security-guide":
            content_dest = self._file_path

        content = self.content_bringer.finish_content_fetch(
            fetching_thread_name, self._policy_data.fingerprint,
            lambda msg: log.info("OSCAP Addon: " + msg), content_dest, _handle_error)

        if not content:
            # this shouldn't happen because error handling is supposed to
            # terminate the addon before finish_content_fetch returns
            _handle_error(Exception())

        remote_content_was_present = (
            not fetching_thread_name
            and self._policy_data.content_type != "scap-security-guide")
        if remote_content_was_present:
            content.add_file(self._content_path)

        try:
            # just check that preferred content exists
            _ = self.content_bringer.get_preferred_content(content)
        except Exception as exc:
            terminate(str(exc))


class EvaluateRulesTask(Task):
    """The installation task for the evaluation of the rules."""

    def __init__(self, policy_data, content_path, tailoring_path):
        """Create a task."""
        super().__init__()
        self._policy_data = policy_data
        self._content_path = content_path
        self._tailoring_path = tailoring_path

    @property
    def name(self):
        return "Evaluate the rules"

    def run(self):
        """Run the task."""
        rule_data = self._initialize_rules()
        self._evaluate_rules(rule_data)

    def _initialize_rules(self):
        try:
            rule_data = rule_handling.get_rule_data_from_content(
                self._policy_data.profile_id, self._content_path,
                self._policy_data.datastream_id, self._policy_data.xccdf_id,
                self._tailoring_path)
            return rule_data

        except common.OSCAPaddonError as e:
            _handle_error(e)


    def _evaluate_rules(self, rule_data):
        # evaluate rules, do automatic fixes and stop if something that cannot
        # be fixed automatically is wrong
        all_messages = rule_data.eval_rules(None, None)
        fatal_messages = [message for message in all_messages
                          if message.type == common.MESSAGE_TYPE_FATAL]
        if any(fatal_messages):
            msg_lines = [_("Wrong configuration detected!")]
            msg_lines.extend([m.text for m in fatal_messages])
            terminate("\n".join(msg_lines))
            return

        # add packages needed on the target system to the list of packages
        # that are requested to be installed
        packages_data = get_packages_data()
        pkgs_to_install = list(REQUIRED_PACKAGES)

        if self._policy_data.content_type == "scap-security-guide":
            pkgs_to_install.append("scap-security-guide")

        for pkg in pkgs_to_install:
            if pkg not in packages_data.packages:
                packages_data.packages.append(pkg)

        set_packages_data(packages_data)


class InstallContentTask(Task):
    """The installation task for installation of the content."""

    def __init__(self, sysroot, policy_data, file_path,
                 content_path, tailoring_path, target_directory):
        """Create a task."""
        super().__init__()
        self._sysroot = sysroot
        self._policy_data = policy_data
        self._file_path = file_path
        self._content_path = content_path
        self._tailoring_path = tailoring_path
        self._target_directory = target_directory

    @property
    def name(self):
        return "Install the content"

    def run(self):
        """Run the task."""
        target_content_dir = utils.join_paths(
            self._sysroot,
            self._target_directory
        )

        utils.ensure_dir_exists(target_content_dir)

        if self._policy_data.content_type == "scap-security-guide":
            pass  # nothing needed
        elif self._policy_data.content_type == "datastream":
            shutil.copy2(self._content_path, target_content_dir)
        elif self._policy_data.content_type == "rpm":
            # copy the RPM to the target system
            shutil.copy2(self._file_path, target_content_dir)

            # get the path of the RPM
            content_name = common.get_content_name(self._policy_data)
            package_path = utils.join_paths(self._target_directory, content_name)

            # and install it with yum
            ret = util.execInSysroot(
                "yum", ["-y", "--nogpg", "install", package_path]
            )

            if ret != 0:
                raise common.ExtractionError(
                    "Failed to install content RPM to the target system"
                )
        else:
            pattern = utils.join_paths(common.INSTALLATION_CONTENT_DIR, "*")
            utils.universal_copy(pattern, target_content_dir)

        if os.path.exists(self._tailoring_path):
            shutil.copy2(self._tailoring_path, target_content_dir)


class RemediateSystemTask(Task):
    """The installation task for running the remediation."""

    def __init__(self, sysroot, policy_data, target_content_path,
                 target_tailoring_path):
        """Create a task."""
        super().__init__()
        self._sysroot = sysroot
        self._policy_data = policy_data
        self._target_content_path = target_content_path
        self._target_tailoring_path = target_tailoring_path

    @property
    def name(self):
        return "Remediate the system"

    def run(self):
        """Run the task."""
        common.run_oscap_remediate(
            self._policy_data.profile_id,
            self._target_content_path,
            self._policy_data.datastream_id,
            self._policy_data.xccdf_id,
            self._target_tailoring_path,
            chroot=self._sysroot
        )
