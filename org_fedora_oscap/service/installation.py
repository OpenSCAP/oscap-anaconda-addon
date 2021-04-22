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
from org_fedora_oscap.common import _

log = logging.getLogger(__name__)


class FetchContentTask(Task):
    """The installation task for fetching the content."""

    def __init__(self, policy_data, file_path, content_path):
        """Create a task."""
        super().__init__()
        self._policy_data = policy_data
        self._file_path = file_path
        self._content_path = content_path

    @property
    def name(self):
        return "Fetch the content"

    def run(self):
        """Run the task."""
        # Is the content available?
        if os.path.exists(self._content_path):
            log.debug("Content is already available. Skip.")
            return

        if os.path.exists(self._file_path):
            log.debug("Content is already available. Skip.")
            return

        try:
            data_fetch.fetch_data(
                self._policy_data.content_url,
                self._file_path,
                self._policy_data.certificates
            )

            # RPM is an archive at this phase
            if self._policy_data.content_type in ("archive", "rpm"):
                # extract the content
                common.extract_data(
                    self._file_path,
                    common.INSTALLATION_CONTENT_DIR,
                    [self._policy_data.content_path]
                )

        except (common.OSCAPaddonError, data_fetch.DataFetchError) as e:
            log.error("Failed to fetch SCAP content!")

            raise NonCriticalInstallationError(_(
                "There was an error fetching the security content:\n%s\n"
                "The installation should be aborted."
            ) % e)


class CheckFingerprintTask(Task):
    """The installation task for checking the fingerprint."""

    def __init__(self, policy_data, file_path):
        """Create a task."""
        super().__init__()
        self._policy_data = policy_data
        self._file_path = file_path

    @property
    def name(self):
        return "Check the fingerprint"

    def run(self):
        """Run the task."""
        if not self._policy_data.fingerprint:
            log.debug("No fingerprint is provided. Skip.")
            return

        hash_obj = utils.get_hashing_algorithm(self._policy_data.fingerprint)
        digest = utils.get_file_fingerprint(self._file_path, hash_obj)

        if digest != self._policy_data.fingerprint:
            log.error("Failed to fetch and initialize SCAP content!")

            raise NonCriticalInstallationError(_(
                "The integrity check of the security content failed.\n" +
                "The installation should be aborted."
            ))


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
            rules = common.get_fix_rules_pre(
                self._policy_data.profile_id,
                self._content_path,
                self._policy_data.datastream_id,
                self._policy_data.xccdf_id,
                self._tailoring_path
            )

            # parse and store rules
            rule_data = rule_handling.RuleData()

            for rule in rules.splitlines():
                rule_data.new_rule(rule)

            return rule_data

        except common.OSCAPaddonError as e:
            log.error("Failed to load SCAP content!")

            raise NonCriticalInstallationError(_(
                "There was an error loading the security content:\n%s\n"
                "The installation should be aborted."
            ) % e)

    def _evaluate_rules(self, rule_data):
        # evaluate rules, do automatic fixes and stop if something that cannot
        # be fixed automatically is wrong
        all_messages = rule_data.eval_rules(None, None)
        fatal_messages = [m for m in all_messages if m.type == common.MESSAGE_TYPE_FATAL]

        if any(fatal_messages):
            raise NonCriticalInstallationError(_(
                "There was a wrong configuration detected:\n%s\n"
                "The installation should be aborted."
            ) % "\n".join(message.text for message in fatal_messages))


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
