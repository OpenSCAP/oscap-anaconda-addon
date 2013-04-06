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

from org_fedora_oscap.common import OSCAPaddonError

# everything else should be private
__all__ = ["RuleData"]

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
