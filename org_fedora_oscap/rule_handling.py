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

"""
Module with various classes for handling pre-installation rules.

"""

import optparse
import shlex
import logging

from pyanaconda.pwpolicy import F22_PwPolicyData
from pyanaconda.core.constants import (
    FIREWALL_ENABLED, FIREWALL_DISABLED, FIREWALL_USE_SYSTEM_DEFAULTS)
from pyanaconda.modules.common.constants.objects import FIREWALL, BOOTLOADER, DEVICE_TREE
from pyanaconda.modules.common.constants.services import NETWORK, STORAGE, USERS

from org_fedora_oscap import common
from org_fedora_oscap.common import OSCAPaddonError, RuleMessage

# everything else should be private
__all__ = ["RuleData"]


# Mapping of packages to package environments and/or groups that depends on them
# See also https://access.redhat.com/solutions/1201413 how to get group IDs.
# on RHEL8, use e.g. grep -R "<id>" /var/cache/dnf/*
ESSENTIAL_PACKAGES = {
    "xorg-x11-server-common": {
        "env": ["graphical-server-environment", "workstation-product-environment"],
        "groups": ["workstation-product-environment"],
    },
    "nfs-utils": {
        "env": ["graphical-server-environment", "workstation-product-environment"],
        "groups": ["workstation-product-environment"],
    },
    "tftp": {
        "groups": ["network-server"],
    },
    "abrt": {
        "groups": ["debugging"],
    },
    "gssproxy": {
        "groups": ["file-server"],
    },
}

log = logging.getLogger("anaconda")

_ = common._


def get_rule_data_from_content(profile_id, content_path, ds_id="", xccdf_id="", tailoring_path=""):
    rules = common.get_fix_rules_pre(
        profile_id, content_path, ds_id, xccdf_id, tailoring_path)

    # parse and store rules with a clean RuleData instance
    rule_data = RuleData()
    for rule in rules.splitlines():
        rule_data.new_rule(rule)
    return rule_data


# TODO: use set instead of list for mount options?
def parse_csv(option, opt_str, value, parser):
    for item in value.split(","):
        if item:
            parser.values.ensure_value(option.dest, []).append(item)


class ModifiedOptionParserException(Exception):
    """Exception to be raised by ModifiedOptionParser."""
    pass


class ModifiedOptionParser(optparse.OptionParser):
    """Overrides error behavior of OptionParser."""
    def error(self, msg):
        raise ModifiedOptionParserException(msg)

    def exit(self, status=0, msg=None):
        raise ModifiedOptionParserException(msg)


PART_RULE_PARSER = ModifiedOptionParser()
PART_RULE_PARSER.add_option("--mountoptions", dest="mount_options",
                            action="callback", callback=parse_csv, nargs=1,
                            type="string")

PASSWD_RULE_PARSER = ModifiedOptionParser()
PASSWD_RULE_PARSER.add_option("--minlen", dest="minlen", action="store",
                              default=0, type="int")

PACKAGE_RULE_PARSER = ModifiedOptionParser()
PACKAGE_RULE_PARSER.add_option("--add", dest="add_pkgs", action="append",
                               type="string")
PACKAGE_RULE_PARSER.add_option("--remove", dest="remove_pkgs", action="append",
                               type="string")

BOOTLOADER_RULE_PARSER = ModifiedOptionParser()
BOOTLOADER_RULE_PARSER.add_option("--passwd", dest="passwd", action="store_true",
                                  default=False)

KDUMP_RULE_PARSER = ModifiedOptionParser()
KDUMP_RULE_PARSER.add_option("--enable", action="store_true",
                             dest="kdenabled", default=None)
KDUMP_RULE_PARSER.add_option("--disable", action="store_false",
                             dest="kdenabled", default=None)

FIREWALL_RULE_PARSER = ModifiedOptionParser()
FIREWALL_RULE_PARSER.add_option("--enable", action="store_true",
                                dest="fwenabled", default=None)
FIREWALL_RULE_PARSER.add_option("--disable", action="store_false",
                                dest="fwenabled", default=None)
FIREWALL_RULE_PARSER.add_option("--service", dest="add_svcs", action="append",
                                type="string")
FIREWALL_RULE_PARSER.add_option("--port", dest="add_port", action="append",
                                type="string")
FIREWALL_RULE_PARSER.add_option("--trust", dest="add_trust", action="append",
                                type="string")
FIREWALL_RULE_PARSER.add_option("--remove-service", dest="remove_svcs",
                                action="append", type="string")


class RuleHandler(object):
    """Base class for the rule handlers."""

    def eval_rules(self, ksdata, storage, report_only=False):
        """
        Method that should check the current state (as defined by the ksdata
        and storage parameters) against the rules the instance of RuleHandler
        holds. Depending on the value of report_only it should fix the state
        with changes that can be done automatically or not and return the list
        of warnings and errors for fixes that need to be done manually together
        with info messages about the automatic changes. One should make sure
        this method is called with report_only set to False at least once so
        that the automatic fixes are done.

        :param ksdata: data representing the values set by user
        :type ksdata: pykickstart.base.BaseHandler
        :param storage: object storing storage-related information
                        (disks, partitioning, bootloader, etc.)
        :type storage: blivet.Blivet
        :param report_only: whether to do fixing or just report information
        :type report_only: bool
        :return: errors and warnings for fixes that need to be done manually
                 and info messages about the automatic changes
        :rtype: list of common.RuleMessage objects

        """

        return []

    def revert_changes(self, ksdata, storage):
        """
        Method that should revert all changes done by the previous calls of the
        eval_rules method with the report_only set to False.

        :see: eval_rules

        """

        # inheriting classes are supposed to override this
        pass


class UknownRuleError(OSCAPaddonError):
    """Exception class for cases when an uknown rule is to be processed."""

    pass


class RuleData(RuleHandler):
    """Class holding data parsed from the applied rules."""

    def __init__(self):
        """Constructor initializing attributes."""

        self._part_rules = PartRules()
        self._passwd_rules = PasswdRules()
        self._package_rules = PackageRules()
        self._bootloader_rules = BootloaderRules()
        self._kdump_rules = KdumpRules()
        self._firewall_rules = FirewallRules()

        self._rule_handlers = (self._part_rules, self._passwd_rules,
                               self._package_rules, self._bootloader_rules,
                               self._kdump_rules, self._firewall_rules,
                               )

    def __str__(self):
        """Standard method useful for debugging and testing."""

        ret = ""

        part_strs = str(self._part_rules)
        if part_strs:
            ret += part_strs

        passwd_str = str(self._passwd_rules)
        if passwd_str:
            ret += "\n" + passwd_str

        packages_str = str(self._package_rules)
        if packages_str:
            ret += "\n" + packages_str

        firewall_str = str(self._firewall_rules)
        if firewall_str:
            ret += "\n" + firewall_str

        return ret

    def new_rule(self, rule):
        """
        Method that handles a single rule line (e.g. "part /tmp").

        :param rule: a single rule line
        :type rule: str

        """

        actions = {"part": self._new_part_rule,
                   "passwd": self._new_passwd_rule,
                   "package": self._new_package_rule,
                   "bootloader": self._new_bootloader_rule,
                   "kdump": self._new_kdump_rule,
                   "firewall": self._new_firewall_rule,
                   }

        rule = rule.strip()
        if not rule:
            return

        first_word = rule.split(None, 1)[0]
        try:
            actions[first_word](rule)
        except (ModifiedOptionParserException, KeyError) as e:
            log.warning("Unknown OSCAP Addon rule '{}': {}".format(rule, e))

    def eval_rules(self, ksdata, storage, report_only=False):
        """:see: RuleHandler.eval_rules"""

        messages = []

        # evaluate all subgroups of rules
        for rule_handler in self._rule_handlers:
            messages += rule_handler.eval_rules(ksdata, storage, report_only)

        return messages

    def revert_changes(self, ksdata, storage):
        """:see: RuleHandler.revert_changes"""

        # revert changes in all subgroups of rules
        for rule_handler in self._rule_handlers:
            rule_handler.revert_changes(ksdata, storage)

    def _new_part_rule(self, rule):
        args = shlex.split(rule)
        (opts, args) = PART_RULE_PARSER.parse_args(args)

        # args contain both "part" and mount point (e.g. "/tmp")
        mount_point = args[1]

        self._part_rules.ensure_mount_point(mount_point)

        if opts.mount_options:
            part_data = self._part_rules[mount_point]
            part_data.add_mount_options(opts.mount_options)

    def _new_passwd_rule(self, rule):
        args = shlex.split(rule)
        (opts, args) = PASSWD_RULE_PARSER.parse_args(args)

        self._passwd_rules.update_minlen(opts.minlen)

    def _new_package_rule(self, rule):
        args = shlex.split(rule)
        (opts, args) = PACKAGE_RULE_PARSER.parse_args(args)

        self._package_rules.add_packages(opts.add_pkgs)
        self._package_rules.remove_packages(opts.remove_pkgs)

    def _new_bootloader_rule(self, rule):
        args = shlex.split(rule)
        (opts, args) = BOOTLOADER_RULE_PARSER.parse_args(args)

        if opts.passwd:
            self._bootloader_rules.require_password()

    def _new_kdump_rule(self, rule):
        args = shlex.split(rule)
        (opts, args) = KDUMP_RULE_PARSER.parse_args(args)

        self._kdump_rules.kdump_enabled(opts.kdenabled)

    def _new_firewall_rule(self, rule):
        args = shlex.split(rule)
        (opts, args) = FIREWALL_RULE_PARSER.parse_args(args)

        self._firewall_rules.add_services(opts.add_svcs)
        self._firewall_rules.remove_services(opts.remove_svcs)
        self._firewall_rules.add_trusts(opts.add_trust)
        self._firewall_rules.add_ports(opts.add_port)
        self._firewall_rules.firewall_enabled(opts.fwenabled)

    @property
    def passwd_rules(self):
        # needed for fixups in GUI
        return self._passwd_rules


class PartRules(RuleHandler):
    """Simple class holding data from the rules affecting partitioning."""

    def __init__(self):
        """Constructor initializing attributes."""

        self._rules = dict()

    def __str__(self):
        """Standard method useful for debugging and testing."""

        return "\n".join(str(rule) for rule in self._rules.values())

    def __getitem__(self, key):
        """Method to support dictionary-like syntax."""

        return self._rules[key]

    def __setitem__(self, key, value):
        """Method to support dictionary-like syntax."""

        self._rules[key] = value

    def __delitem__(self, key):
        """One of the methods needed to implement a container."""

        self._rules.__delitem__(key)

    def __len__(self):
        """One of the methods needed to implement a container."""

        return self._rules.__len__()

    def __contains__(self, key):
        """Method needed for the 'in' operator to work."""

        return key in self._rules

    def ensure_mount_point(self, mount_point):
        if mount_point not in self._rules:
            self._rules[mount_point] = PartRule(mount_point)

    def eval_rules(self, ksdata, storage, report_only=False):
        """:see: RuleHandler.eval_rules"""

        messages = []
        for part_rule in self._rules.values():
            messages += part_rule.eval_rules(ksdata, storage, report_only)

        return messages

    def revert_changes(self, ksdata, storage):
        """:see: RuleHandler.revert_changes"""

        for part_rule in self._rules.values():
            part_rule.revert_changes(ksdata, storage)


class PartRule(RuleHandler):
    """Simple class holding rule data for a single partition/mount point."""

    def __init__(self, mount_point):
        """
        Constructor initializing attributes.

        :param mount_point: the mount point the object holds data for
        :type mount_point: str

        """

        self._mount_point = mount_point
        self._mount_options = []
        self._added_mount_options = []

    def __str__(self):
        """Standard method useful for debugging and testing."""

        ret = "part %s" % self._mount_point
        if self._mount_options:
            ret += " --mountoptions=%s" % ",".join(self._mount_options)

        return ret

    def add_mount_options(self, mount_options):
        """
        Add  new mount options (do not add duplicates).

        :param mount_options: list of mount options to be added
        :type mount_options: list of strings

        """

        self._mount_options.extend(opt for opt in mount_options
                                   if opt not in self._mount_options)

    def eval_rules(self, ksdata, storage, report_only=False):
        """:see: RuleHandler.eval_rules"""
        device_tree = STORAGE.get_proxy(DEVICE_TREE)
        mount_points = device_tree.GetMountPoints()
        messages = []

        if self._mount_point not in mount_points:
            msg = _("{0} must be on a separate partition or logical "
                    "volume and has to be created in the "
                    "partitioning layout before installation can occur "
                    "with a security profile").format(self._mount_point)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_FATAL, msg))

            # mount point doesn't exist, nothing more can be found here
            return messages

        # template for the message
        msg_tmpl = _("mount option '%(mount_option)s' added for "
                     "the mount point %(mount_point)s")

        # add message for every option already added
        for opt in self._added_mount_options:
            msg = msg_tmpl % {"mount_option": opt,
                              "mount_point": self._mount_point}
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))

        # mount point to be created during installation
        target_name = mount_points[self._mount_point]
        mount_options = device_tree.GetDeviceMountOptions(target_name)

        # generator for the new options that should be added
        new_opts = (opt for opt in self._mount_options
                    if opt not in mount_options.split(","))

        # add message for every mount option added
        for opt in new_opts:
            msg = msg_tmpl % {"mount_option": opt,
                              "mount_point": self._mount_point}

            # add message for the mount option in any case
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))

            # add new options to the target mount point if not reporting only
            if not report_only:
                mount_options += ",%s" % opt
                self._added_mount_options.append(opt)

        if new_opts and not report_only:
            device_tree.SetDeviceMountOptions(target_name, mount_options)

        return messages

    def revert_changes(self, ksdata, storage):
        """
        Removes the mount options added to the mount point by this PartRule
        instance.

        :see: RuleHandler.revert_changes

        """
        device_tree = STORAGE.get_proxy(DEVICE_TREE)
        mount_points = device_tree.GetMountPoints()

        if self._mount_point not in mount_points:
            # mount point doesn't exist, nothing can be reverted
            return

        # mount point to be created during installation
        target_name = mount_points[self._mount_point]

        # mount options to be defined for the created mount point
        mount_options = device_tree.GetDeviceMountOptions(target_name)

        # generator of the options that should remain
        result_opts = (opt for opt in mount_options.split(",")
                       if opt not in self._added_mount_options)

        # set the new list of options
        mount_options = ",".join(result_opts)
        device_tree.SetDeviceMountOptions(target_name, mount_options)

        # reset the remembered added mount options
        self._added_mount_options = []


class PasswdRules(RuleHandler):
    """Simple class holding data from the rules affecting passwords."""

    def __init__(self):
        """Constructor initializing attributes."""

        self._minlen = 0
        self._created_policy = False
        self._orig_minlen = None
        self._orig_strict = None

    def __str__(self):
        """Standard method useful for debugging and testing."""

        if self._minlen > 0:
            return "passwd --minlen=%d" % self._minlen
        else:
            return ""

    def update_minlen(self, minlen):
        """Update password minimal length requirements."""

        if minlen > self._minlen:
            self._minlen = minlen

    def eval_rules(self, ksdata, storage, report_only=False):
        """:see: RuleHandler.eval_rules"""

        if self._minlen == 0:
            # no password restrictions, nothing to be done here
            return []

        ret = []

        users_proxy = USERS.get_proxy()

        if not users_proxy.IsRootPasswordSet:
            # root password was not set

            msg = _("make sure to create password with minimal length of %d "
                    "characters") % self._minlen
            ret = [RuleMessage(self.__class__,
                               common.MESSAGE_TYPE_WARNING, msg)]
        else:
            # root password set
            if users_proxy.IsRootPasswordCrypted:
                msg = _("cannot check root password length (password is crypted)")
                log.warning("cannot check root password length (password is crypted)")
                return [RuleMessage(self.__class__,
                                    common.MESSAGE_TYPE_WARNING, msg)]
            elif len(users_proxy.RootPassword) < self._minlen:
                # too short
                msg = _("root password is too short, a longer one with at "
                        "least %d characters is required") % self._minlen
                ret = [RuleMessage(self.__class__,
                                   common.MESSAGE_TYPE_FATAL, msg)]
            else:
                ret = []

        if report_only:
            return ret

        # set the policy in any case (so that a weaker password is not entered)
        pw_policy = ksdata.anaconda.pwpolicy.get_policy("root")
        if pw_policy is None:
            pw_policy = F22_PwPolicyData()
            log.info("OSCAP addon: setting password policy %s" % pw_policy)
            ksdata.anaconda.pwpolicy.policyList.append(pw_policy)
            log.info("OSCAP addon: password policy list: %s" % ksdata.anaconda.pwpolicy.policyList)
            self._created_policy = True

        self._orig_minlen = pw_policy.minlen
        self._orig_strict = pw_policy.strict
        pw_policy.minlen = self._minlen
        pw_policy.strict = True

        return ret

    def revert_changes(self, ksdata, storage):
        """:see: RuleHander.revert_changes"""

        pw_policy = ksdata.anaconda.pwpolicy.get_policy("root")
        if self._created_policy:
            log.info("OSCAP addon: removing password policy: %s" % pw_policy)
            ksdata.anaconda.pwpolicy.policyList.remove(pw_policy)
            log.info("OSCAP addon: password policy list: %s" % ksdata.anaconda.pwpolicy.policyList)
            self._created_policy = False
        else:
            if self._orig_minlen is not None:
                pw_policy.minlen = self._orig_minlen
                self._orig_minlen = None
            if self._orig_strict is not None:
                pw_policy.strict = self._orig_strict
                self._orig_strict = None


class PackageRules(RuleHandler):
    """Simple class holding data from the rules affecting installed packages.

    """

    def __init__(self):
        """Constructor setting the initial value of attributes."""

        self._add_pkgs = set()
        self._remove_pkgs = set()

        self._added_pkgs = set()
        self._removed_pkgs = set()

    def add_packages(self, packages):
        """
        New packages that should be added.

        :param packages: packages to be added
        :type packages: iterable

        """

        if packages:
            self._add_pkgs.update(packages)

    def remove_packages(self, packages):
        """
        New packages that should be removed.

        :param packages: packages to be removed
        :type packages: iterable

        """

        if packages:
            self._remove_pkgs.update(packages)

    def __str__(self):
        """Standard method useful for debugging and testing."""

        ret = "packages"
        adds = " ".join("--add=%s" % package for package in self._add_pkgs)
        if adds:
            ret += " " + adds

        rems = " ".join("--remove=%s" % package
                        for package in self._remove_pkgs)
        if rems:
            ret += " " + rems

        return ret

    def _package_is_essential(self, package_name, ksdata_packages):
        if package_name not in ESSENTIAL_PACKAGES:
            return False
        if package_name in ksdata_packages.packageList:
            return True
        selected_install_env = ksdata_packages.environment
        if selected_install_env in ESSENTIAL_PACKAGES[package_name].get("env", []):
            return True
        selected_install_groups_names = {g.name for g in ksdata_packages.groupList}
        for g in ESSENTIAL_PACKAGES[package_name].get("groups", []):
            if g in selected_install_groups_names:
                return True
        return False

    def eval_rules(self, ksdata, storage, report_only=False):
        """:see: RuleHandler.eval_rules"""

        messages = []

        # add messages for the already added packages
        for pkg in self._added_pkgs:
            msg = _("package '%s' has been added to the list of to be installed "
                    "packages" % pkg)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))

        # packages, that should be added
        packages_to_add = (pkg for pkg in self._add_pkgs
                           if pkg not in ksdata.packages.packageList)

        for pkg in packages_to_add:
            # add the package unless already added
            if not report_only:
                self._added_pkgs.add(pkg)
                ksdata.packages.packageList.append(pkg)

            msg = _("package '%s' has been added to the list of to be installed "
                    "packages" % pkg)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))

        # now do the same for the packages that should be excluded
        # add messages for the already excluded packages
        for pkg in self._removed_pkgs:
            if self._package_is_essential(pkg, ksdata.packages):
                msg = _(
                    "package '{package}' has been added to the list "
                    "of excluded packages, but it can't be removed "
                    "from the current software selection without breaking the installation."
                    .format(package=pkg))
                messages.append(RuleMessage(self.__class__,
                                            common.MESSAGE_TYPE_FATAL, msg))
            else:
                msg = _("package '%s' has been added to the list of excluded "
                        "packages" % pkg)
                messages.append(RuleMessage(self.__class__,
                                            common.MESSAGE_TYPE_INFO, msg))

        # packages, that should be added
        packages_to_remove = (pkg for pkg in self._remove_pkgs
                              if pkg not in ksdata.packages.excludedList)

        for pkg in packages_to_remove:
            # exclude the package unless already excluded
            if not report_only:
                self._removed_pkgs.add(pkg)
                ksdata.packages.excludedList.append(pkg)

            msg = _("package '%s' has been added to the list of excluded "
                    "packages" % pkg)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))

        return messages

    def revert_changes(self, ksdata, storage):
        """:see: RuleHander.revert_changes"""

        # remove all packages this handler added
        for pkg in self._added_pkgs:
            if pkg in ksdata.packages.packageList:
                ksdata.packages.packageList.remove(pkg)

        # remove all packages this handler excluded
        for pkg in self._removed_pkgs:
            if pkg in ksdata.packages.excludedList:
                ksdata.packages.excludedList.remove(pkg)

        self._added_pkgs = set()
        self._removed_pkgs = set()


class BootloaderRules(RuleHandler):
    """Simple class holding data from the rules affecting bootloader."""

    def __init__(self):
        """Constructor setting the initial value of attributes."""

        self._require_password = False

    def require_password(self):
        """Requests the bootloader password should be required."""

        self._require_password = True

    def __str__(self):
        """Standard method useful for debugging and testing."""

        ret = "bootloader"

        if self._require_password:
            ret += " --passwd"

        return ret

    def eval_rules(self, ksdata, storage, report_only=False):
        """:see: RuleHandler.eval_rules"""

        bootloader_proxy = STORAGE.get_proxy(BOOTLOADER)

        if self._require_password and not bootloader_proxy.IsPasswordSet:
            # TODO: Anaconda provides a way to set bootloader password:
            # bootloader_proxy.SetEncryptedPassword(...)
            # We don't support setting the bootloader password yet,
            # but we shouldn't stop the installation, just because of that.
            return [RuleMessage(self.__class__, common.MESSAGE_TYPE_WARNING,
                                "boot loader password not set up")]
        else:
            return []

    # nothing to be reverted for now


class KdumpRules(RuleHandler):
    """Simple class holding data from the rules affecting the kdump addon."""

    def __init__(self):
        """Constructor setting the initial value of attributes."""

        self._kdump_enabled = None
        self._kdump_default_enabled = None

    def kdump_enabled(self, kdenabled):
        """Enable or Disable Kdump"""

        if kdenabled is not None:
            self._kdump_enabled = kdenabled

    def __str__(self):
        """Standard method useful for debugging and testing."""

        ret = "kdump"

        if self._kdump_enabled is True:
            ret += " --enable"

        if self._kdump_enabled is False:
            ret += " --disable"

        return ret

    def eval_rules(self, ksdata, storage, report_only=False):
        """:see: RuleHandler.eval_rules"""

        messages = []

        if self._kdump_enabled is None:
            return []
        elif self._kdump_enabled is False:
            msg = _("Kdump will be disabled on startup")
        elif self._kdump_enabled is True:
            msg = _("Kdump will be enabled on startup")

        messages.append(RuleMessage(self.__class__,
                                    common.MESSAGE_TYPE_INFO, msg))

        if not report_only:
            try:
                if self._kdump_default_enabled is None:
                    # Kdump addon default startup setting
                    self._kdump_default_enabled = ksdata.addons.com_redhat_kdump.enabled
                ksdata.addons.com_redhat_kdump.enabled = self._kdump_enabled
            except AttributeError:
                log.warning("com_redhat_kdump is not installed. "
                            "Skipping kdump configuration")

        return messages

    def revert_changes(self, ksdata, storage):
        """:see: RuleHander.revert_changes"""

        try:
            if self._kdump_enabled is not None:
                ksdata.addons.com_redhat_kdump.enabled = self._kdump_default_enabled
        except AttributeError:
            log.warning("com_redhat_kdump is not installed. "
                        "Skipping reverting kdump configuration")

        self._kdump_enabled = None
        self._kdump_default_enabled = None


class FirewallRules(RuleHandler):
    """Simple class holding data from the rules affecting firewall configurations."""

    def __init__(self):
        """Constructor setting the initial value of attributes."""

        self._add_svcs = set()
        self._remove_svcs = set()
        self._add_trusts = set()
        self._add_ports = set()

        self._added_svcs = set()
        self._added_ports = set()
        self._added_trusts = set()
        self._removed_svcs = set()

        self._new_services_to_add = set()
        self._new_ports_to_add = set()
        self._new_trusts_to_add = set()
        self._new_services_to_remove = set()

        self._firewall_enabled = None
        self._firewall_default_state = None

    def add_services(self, services):
        """
        Services that should be allowed through firewall.

        :param services: services to be added
        :type services: iterable

        """

        if services:
            self._add_svcs.update(services)

    def add_ports(self, ports):
        """
        Ports that should be allowed through firewall.

        :param ports: ports to be added
        :type ports: iterable

        """

        if ports:
            self._add_ports.update(ports)

    def add_trusts(self, trusts):
        """
        trusts that should be allowed through firewall.

        :param trusts: trusts to be added
        :type trusts: iterable

        """

        if trusts:
            self._add_trusts.update(trusts)

    def remove_services(self, services):
        """
        New services that should not be allowed through firewall.

        :param services: services to be removed
        :type services: iterable

        """

        if services:
            self._remove_svcs.update(services)

    def firewall_enabled(self, fwenabled):
        """Enable or disable firewall"""

        if fwenabled is not None:
            self._firewall_enabled = fwenabled

    def __str__(self):
        """Standard method useful for debugging and testing."""

        ret = "firewall"

        if self._firewall_enabled is True:
            ret += " --enable"

        if self._firewall_enabled is False:
            ret += " --disable"

        adds = " ".join("--service=%s" % service
                        for service in self._add_svcs)
        if adds:
            ret += " " + adds

        rems = " ".join("--remove-service=%s" % service
                        for service in self._remove_svcs)
        if rems:
            ret += " " + rems

        ports = " ".join("--port=%s" % port
                         for port in self._add_ports)
        if ports:
            ret += " " + ports

        trusts = " ".join("--trust=%s" % trust
                          for trust in self._add_trusts)
        if trusts:
            ret += " " + trusts

        return ret

    def eval_rules(self, ksdata, storage, report_only=False):
        """:see: RuleHandler.eval_rules"""

        firewall_proxy = NETWORK.get_proxy(FIREWALL)
        messages = []

        if self._firewall_default_state is None:
            # firewall default startup setting
            self._firewall_default_state = firewall_proxy.FirewallMode

        if self._firewall_enabled is False:
            msg = _("Firewall will be disabled on startup")
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))
            if not report_only:
                firewall_proxy.SetFirewallMode(FIREWALL_DISABLED)

        elif self._firewall_enabled is True:
            msg = _("Firewall will be enabled on startup")
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))
            if not report_only:
                firewall_proxy.SetFirewallMode(FIREWALL_ENABLED)

        # add messages for the already added services
        for svc in self._added_svcs:
            msg = _("service '%s' has been added to the list of services to be "
                    "added to the firewall" % svc)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))

        # add messages for the already added ports
        for port in self._added_ports:
            msg = _("port '%s' has been added to the list of ports to be "
                    "added to the firewall" % port)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))

        # add messages for the already added trusts
        for trust in self._added_trusts:
            msg = _("trust '%s' has been added to the list of trusts to be "
                    "added to the firewall" % trust)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))

        # services, that should be added
        self._new_services_to_add = {
            svc for svc in self._add_svcs
            if svc not in firewall_proxy.EnabledServices}

        # ports, that should be added
        self._new_ports_to_add = {
            ports for ports in self._add_ports
            if ports not in firewall_proxy.EnabledPorts}

        # trusts, that should be added
        self._new_trusts_to_add = {
            trust for trust in self._add_trusts
            if trust not in firewall_proxy.Trusts}

        for svc in self._new_services_to_add:
            # add the service unless already added
            if not report_only:
                self._added_svcs.add(svc)

            msg = _("service '%s' has been added to the list of services to be "
                    "added to the firewall" % svc)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))
        if not report_only:
            all_services = list(self._add_svcs.union(set(firewall_proxy.EnabledServices)))
            firewall_proxy.SetEnabledServices(all_services)

        for port in self._new_ports_to_add:
            # add the port unless already added
            if not report_only:
                self._added_ports.add(port)

            msg = _("port '%s' has been added to the list of ports to be "
                    "added to the firewall" % port)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))
        if not report_only:
            all_ports = list(self._add_ports.union(set(firewall_proxy.EnabledPorts)))
            firewall_proxy.SetEnabledPorts(all_ports)

        for trust in self._new_trusts_to_add:
            # add the trust unless already added
            if not report_only:
                self._added_trusts.add(trust)

            msg = _("trust '%s' has been added to the list of trusts to be "
                    "added to the firewall" % trust)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))
        if not report_only:
            all_trusts = list(self._add_trusts.union(set(firewall_proxy.Trusts)))
            firewall_proxy.SetTrusts(all_trusts)

        # now do the same for the services that should be excluded

        # add messages for the already excluded services
        for svc in self._removed_svcs:
            msg = _("service '%s' has been added to the list of services to be "
                    "removed from the firewall" % svc)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))

        # services, that should be excluded
        self._new_services_to_remove = {
            svc for svc in self._remove_svcs
            if svc not in firewall_proxy.DisabledServices}

        for svc in self._new_services_to_remove:
            # exclude the service unless already excluded
            if not report_only:
                self._removed_svcs.add(svc)

            msg = _("service '%s' has been added to the list of services to be "
                    "removed from the firewall" % svc)
            messages.append(RuleMessage(self.__class__,
                                        common.MESSAGE_TYPE_INFO, msg))
        if not report_only:
            all_services = list(self._remove_svcs.union(set(firewall_proxy.DisabledServices)))
            firewall_proxy.SetDisabledServices(all_services)

        return messages

    def revert_changes(self, ksdata, storage):
        """:see: RuleHander.revert_changes"""
        firewall_proxy = NETWORK.get_proxy(FIREWALL)

        if self._firewall_enabled is not None:
            firewall_proxy.SetFirewallMode(self._firewall_default_state)

        # remove all services this handler added
        all_services = firewall_proxy.EnabledServices
        orig_services = set(all_services).difference(self._new_services_to_add)
        firewall_proxy.SetEnabledServices(list(orig_services))

        # remove all ports this handler added
        all_ports = firewall_proxy.EnabledPorts
        orig_ports = set(all_ports).difference(self._new_ports_to_add)
        firewall_proxy.SetEnabledPorts(list(orig_ports))

        # remove all trusts this handler added
        all_trusts = firewall_proxy.Trusts
        orig_trusts = set(all_trusts).difference(self._new_trusts_to_add)
        firewall_proxy.SetTrusts(list(orig_trusts))

        # remove all services this handler excluded
        all_services = firewall_proxy.DisabledServices
        orig_services = set(all_services).difference(self._new_services_to_remove)
        firewall_proxy.SetDisabledServices(list(orig_services))

        self._added_svcs = set()
        self._added_ports = set()
        self._added_trusts = set()
        self._removed_svcs = set()
        self._firewall_enabled = None
        self._firewall_default_state = None
