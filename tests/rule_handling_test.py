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

"""Module with unit tests for the rule_handling.py module"""

import unittest
from org_fedora_oscap import rule_handling

class PartRulesSyntaxSupportTest(unittest.TestCase):
    """Test functionality of the PartRules' methods with syntax support."""

    def setUp(self):
        self.part_rules = rule_handling.PartRules()
        self.part_rules.ensure_mount_point("/tmp")

    # simple tests, shouldn't raise exceptions
    def getitem_test(self):
        self.part_rules["/tmp"]

    def setitem_test(self):
        rule = rule_handling.PartRule("/var/log")
        self.part_rules["/var/log"] = rule

    def len_test(self):
        self.assertEqual(len(self.part_rules), 1)

    def contains_test(self):
        self.assertTrue("/tmp" in self.part_rules)

    def delitem_test(self):
        del(self.part_rules["/tmp"])
        self.assertNotIn("/tmp", self.part_rules)

class RuleDataParsingTest(unittest.TestCase):
    """Test rule data parsing."""

    def setUp(self):
        self.rule_data = rule_handling.RuleData()

    def artificial_test(self):
        self.rule_data.new_rule("  part /tmp --mountoptions=nodev,noauto")
        self.rule_data.new_rule("part /var/log  ")
        self.rule_data.new_rule(" passwd   --minlen=14 ")
        self.rule_data.new_rule("package --add=iptables")
        self.rule_data.new_rule(" package --add=firewalld --remove=telnet")
        self.rule_data.new_rule("package --remove=rlogin --remove=sshd")

        # both partitions should appear in self.rule_data._part_rules
        self.assertIn("/tmp", self.rule_data._part_rules)
        self.assertIn("/var/log", self.rule_data._part_rules)

        # mount options should be parsed
        self.assertIn("nodev", self.rule_data._part_rules["/tmp"]._mount_options)
        self.assertIn("noauto", self.rule_data._part_rules["/tmp"]._mount_options)

        # no mount options for /var/log
        self.assertEqual(self.rule_data._part_rules["/var/log"]._mount_options, [])

        # minimal password length should be parsed and stored correctly
        self.assertEqual(self.rule_data._passwd_rules._minlen, 14)

        self.assertIn("iptables", self.rule_data._package_rules._add_pkgs)
        self.assertIn("firewalld", self.rule_data._package_rules._add_pkgs)
        self.assertIn("telnet", self.rule_data._package_rules._remove_pkgs)
        self.assertIn("rlogin", self.rule_data._package_rules._remove_pkgs)
        self.assertIn("sshd", self.rule_data._package_rules._remove_pkgs)

    def real_output_test(self):
        output = """          
      part /tmp
    
      part /tmp --mountoptions=nodev
    """
        for line in output.splitlines():
            self.rule_data.new_rule(line)

        self.assertIn("/tmp", self.rule_data._part_rules)
        self.assertIn("nodev", self.rule_data._part_rules["/tmp"]._mount_options)

        # should be stripped and merged
        self.assertEqual(str(self.rule_data._part_rules),
                         "part /tmp --mountoptions=nodev")

