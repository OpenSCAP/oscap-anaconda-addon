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
Module with various classes and functions needed by the OSCAP addon that are not
specific to any installation mode (tui, gui, ks).

"""

import optparse
import os
import os.path
import subprocess

# everything else should be private
__all__ = ["RuleData", "run_oscap_remediate", "get_fix_rules_pre"]

RESULTS_PATH = "/root/openscap_data/eval_remediate_results.xml"

PRE_INSTALL_FIX_SYSTEM_ATTR = "urn:redhat:anaconda:pre"

# TODO: use set instead of list for mount options?
def parse_csv(option, opt_str, value, parser):
    for item in value.split(","):
        if item:
            parser.values.ensure_value(option.dest, []).append(item)

PART_RULE_PARSER = optparse.OptionParser()
PART_RULE_PARSER.add_option("--mountoptions", dest="mount_options",
                            action="callback", callback=parse_csv, nargs=1,
                            type="string")

PASSWD_RULE_PARSER = optparse.OptionParser()
PASSWD_RULE_PARSER.add_option("--minlen", dest="minlen", action="store",
                              default=0, type="int")


class OSCAPaddonError(Exception):
    """Exception class for OSCAP addon related errors."""

    pass

def get_fix_rules_pre(profile, fpath, ds_id="", xccdf_id=""):
    """
    Get fix rules for the pre-installation environment for a given profile in a
    given datastream and checklist in a given file.

    :see: run_oscap_remediate
    :see: _run_oscap_gen_fix
    :return: fix rules for a given profile
    :rtype: str

    """

    return _run_oscap_gen_fix(profile, fpath, PRE_INSTALL_FIX_SYSTEM_ATTR,
                              ds_id=ds_id, xccdf_id=xccdf_id)

def _run_oscap_gen_fix(profile, fpath, template, ds_id="", xccdf_id=""):
    """
    Run oscap tool on a given file to get the contents of fix elements with the
    'system' attribute equal to a given template for a given datastream,
    checklist and profile.

    :see: run_oscap_remediate
    :param template: the value of the 'system' attribute of the fix elements
    :type template: str
    :return: oscap tool's stdout
    :rtype: str

    """

    args = ["oscap", "xccdf", "generate", "fix"]
    args.append("--profile=%s" % profile)
    args.append("--template=%s" % template)

    if ds_id:
        args.append("--datastream-id=%s" % ds_id)
    if xccdf_id:
        args.append("--xccdf-id=%s" % xccdf_id)

    args.append(fpath)

    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    except OSError as oserr:
        msg = "Failed to run the oscap tool: %s" % oserr
        raise OSCAPaddonError(msg)

    (stdout, stderr) = proc.communicate()

    # pylint thinks Popen has no attribute returncode
    # pylint: disable-msg=E1101
    if proc.returncode != 0 or stderr:
        msg = "Failed to generate fix rules with the oscap tool: %s" % stderr
        raise OSCAPaddonError(msg)

    return stdout

def run_oscap_remediate(profile, fpath, ds_id="", xccdf_id="", chroot=""):
    """
    Run the evaluation and remediation with the oscap tool on a given file,
    doing the remediation as defined in a given profile defined in a given
    checklist that is a part of a given datastream. If requested, run in
    chroot.

    :param profile: id of the profile that will drive the remediation
    :type profile: str
    :param fpath: path to a file with SCAP content
    :type fpath: str
    :param ds_id: ID of the datastream that contains the checklist defining
                  the profile
    :type ds_id: str
    :param xccdf_id: ID of the checklist that defines the profile
    :type xccdf_id: str
    :param chroot: path to the root the oscap tool should be run in
    :type chroot: str
    :return: oscap tool's stdout (summary of the rules, checks and fixes)
    :rtype: str

    """

    def do_chroot():
        """Helper function doing the chroot if requested."""
        if chroot and chroot != "/":
            os.chroot(chroot)

    # make sure the directory for the results exists
    results_dir = os.path.dirname(RESULTS_PATH)
    if chroot:
        results_dir = os.path.normpath(chroot + "/" + results_dir)
    if not os.path.isdir(results_dir):
        os.makedirs(results_dir)

    args = ["oscap", "xccdf", "eval"]
    args.append("--remediate")
    args.append("--results=%s" % RESULTS_PATH)
    args.append("--profile=%s" % profile)

    if ds_id:
        args.append("--datastream-id=%s" % ds_id)
    if xccdf_id:
        args.append("--xccdf-id=%s" % xccdf_id)

    args.append(fpath)

    try:
        proc = subprocess.Popen(args,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                preexec_fn=do_chroot)
    except OSError as oserr:
        msg = "Failed to run the oscap tool: %s" % oserr
        raise OSCAPaddonError(msg)

    (stdout, stderr) = proc.communicate()

    # save stdout?
    # XXX: is checking return code enough?
    # pylint thinks Popen has no attribute returncode
    # pylint: disable-msg=E1101
    if proc.returncode != 0 or stderr:
        msg = "Content evaluation and remediation with the oscap tool "\
            "failed: %s" % stderr
        raise OSCAPaddonError(msg)

    return stdout

class UknownRuleError(OSCAPaddonError):
    """Exception class for cases when an uknown rule is to be processed."""

    pass

class RuleData(object):
    """Class holding data parsed from the applied rules."""

    def __init__(self):
        """Constructor initializing attributes."""

        self._part_rules = PartRules()
        self._passwd_rules = PasswdRules()

    def __str__(self):
        """Standard method useful for debugging and testing."""

        ret = ""

        part_strs = str(self._part_rules)
        if part_strs:
            ret += part_strs

        passwd_str = str(self._passwd_rules)
        if passwd_str:
            ret += "\n" + passwd_str

        return ret

    def new_rule(self, rule):
        """
        Method that handles a single rule line (e.g. "part /tmp").

        :param rule: a single rule line
        :type rule: str

        """

        actions = { "part" : self._new_part_rule,
                    "passwd" : self._new_passwd_rule,
                    }

        rule = rule.strip()
        if not rule:
            return

        first_word = rule.split(None, 1)[0]
        try:
            actions[first_word](rule)
        except KeyError:
            # should never happen
            # TODO: only log error instead?
            raise UknownRuleError("Unknown rule: '%s'" % first_word)

    def _new_part_rule(self, rule):
        args = rule.split()
        (opts, args) = PART_RULE_PARSER.parse_args(args)

        # args contain both "part" and mount point (e.g. "/tmp")
        mount_point = args[1]

        self._part_rules.ensure_mount_point(mount_point)

        if opts.mount_options:
            part_data = self._part_rules[mount_point]
            part_data.add_mount_options(opts.mount_options)

    def _new_passwd_rule(self, rule):
        args = rule.split()
        (opts, args) = PASSWD_RULE_PARSER.parse_args(args)

        self._passwd_rules.update_minlen(opts.minlen)

class PartRules(object):
    """Simple class holding data from the rules affecting partitioning."""

    def __init__(self):
        """Constructor initializing attributes."""

        self._rules = dict()

    def __str__(self):
        """Standard method useful for debugging and testing."""

        return "\n".join(str(rule) for rule in self._rules.itervalues())

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

class PartRule(object):
    """Simple class holding rule data for a single partition/mount point."""

    def __init__(self, mount_point):
        """
        Constructor initializing attributes.

        :param mount_point: the mount point the object holds data for
        :type mount_point: str

        """

        self._mount_point = mount_point
        self._mount_options = []

    def __str__(self):
        """Standard method useful for debugging and testing."""

        ret = "part %s" % self._mount_point
        if self._mount_options:
            ret +=  " --mountoptions=%s" % ",".join(self._mount_options)

        return ret

    def add_mount_options(self, mount_options):
        """
        Add  new mount options (do not add duplicates).

        :param mount_options: list of mount options to be added
        :type mount_options: list of strings

        """

        self._mount_options.extend(opt for opt in mount_options
                                   if opt not in self._mount_options)

class PasswdRules(object):
    """Simple class holding data from the rules affecting passwords."""

    def __init__(self):
        """Constructor initializing attributes."""

        self._minlen = 0

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