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

"""Module with unit tests for the common.py module"""

import unittest
import os
import mock
from org_fedora_oscap import common

class PartRulesSyntaxSupportTest(unittest.TestCase):
    """Test functionality of the PartRules' methods with syntax support."""

    def setUp(self):
        self.part_rules = common.PartRules()
        self.part_rules.ensure_mount_point("/tmp")

    # simple tests, shouldn't raise exceptions
    def getitem_test(self):
        self.part_rules["/tmp"]

    def setitem_test(self):
        rule = common.PartRule("/var/log")
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
        self.rule_data = common.RuleData()

    def artificial_test(self):
        self.rule_data.new_rule("  part /tmp --mountoptions=nodev,noauto")
        self.rule_data.new_rule("part /var/log  ")
        self.rule_data.new_rule(" passwd   --minlen=14 ")

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

class OSCAPtoolRunningTest(unittest.TestCase):
    def setUp(self):
        self.mock_subprocess = mock.Mock()
        self.mock_subprocess.Popen = mock.Mock()
        self.mock_popen = mock.Mock()
        self.mock_communicate = mock.Mock()

        self.mock_communicate.return_value = ("", "")

        self.mock_popen.communicate = self.mock_communicate
        self.mock_popen.returncode = 0

        self.mock_subprocess.Popen.return_value = self.mock_popen
        self.mock_subprocess.PIPE = mock.Mock()

        self.mock_os = mock.Mock()
        self.mock_os.path = mock.Mock()
        self.mock_os.path.dirname = os.path.dirname
        self.mock_os.path.normpath = os.path.normpath
        self.mock_os.path.isdir = mock.Mock()
        self.mock_os.makedirs = mock.Mock()
        self.mock_os.chroot = mock.Mock()

        self.run_oscap_remediate = common.run_oscap_remediate
        self.run_oscap_remediate.func_globals["subprocess"] = self.mock_subprocess
        self.run_oscap_remediate.func_globals["os"] = self.mock_os

    def run_oscap_remediate_profile_only_test(self):
        self.run_oscap_remediate("myprofile", "my_ds.xml")

        # check calls where done right
        args = ["oscap", "xccdf", "eval", "--remediate",
                "--results=%s" % common.RESULTS_PATH, "--profile=myprofile",
                "my_ds.xml"]

        # it's impossible to check the preexec_func as it is an internal
        # function of the run_oscap_remediate function
        kwargs = { "stdout": self.mock_subprocess.PIPE,
                   "stderr": self.mock_subprocess.PIPE,
                   }

        for arg in args:
            self.assertIn(arg, self.mock_subprocess.Popen.call_args[0][0])
            self.mock_subprocess.Popen.call_args[0][0].remove(arg)

        # nothing else should have been passed
        self.assertEqual(self.mock_subprocess.Popen.call_args[0][0], [])

        for (key, val) in kwargs.iteritems():
            self.assertEqual(kwargs[key],
                             self.mock_subprocess.Popen.call_args[1].pop(key))

        # plus the preexec_fn kwarg should have been passed
        self.assertIn("preexec_fn", self.mock_subprocess.Popen.call_args[1])

    def run_oscap_remediate_with_ds_test(self):
        self.run_oscap_remediate("myprofile", "my_ds.xml", "my_ds_id")

        # check calls where done right
        args = ["oscap", "xccdf", "eval", "--remediate",
                "--results=%s" % common.RESULTS_PATH, "--profile=myprofile",
                "--datastream-id=my_ds_id", "my_ds.xml"]

        # it's impossible to check the preexec_func as it is an internal
        # function of the run_oscap_remediate function
        kwargs = { "stdout": self.mock_subprocess.PIPE,
                   "stderr": self.mock_subprocess.PIPE,
                   }

        for arg in args:
            self.assertIn(arg, self.mock_subprocess.Popen.call_args[0][0])
            self.mock_subprocess.Popen.call_args[0][0].remove(arg)

        # nothing else should have been passed
        self.assertEqual(self.mock_subprocess.Popen.call_args[0][0], [])

        for (key, val) in kwargs.iteritems():
            self.assertEqual(kwargs[key],
                             self.mock_subprocess.Popen.call_args[1].pop(key))

        # plus the preexec_fn kwarg should have been passed
        self.assertIn("preexec_fn", self.mock_subprocess.Popen.call_args[1])

    def run_oscap_remediate_with_ds_xccdf_test(self):
        self.run_oscap_remediate("myprofile", "my_ds.xml", "my_ds_id",
                                 "my_xccdf_id")

        # check calls where done right
        args = ["oscap", "xccdf", "eval", "--remediate",
                "--results=%s" % common.RESULTS_PATH, "--profile=myprofile",
                "--datastream-id=my_ds_id", "--xccdf-id=my_xccdf_id",
                "my_ds.xml"]

        # it's impossible to check the preexec_func as it is an internal
        # function of the run_oscap_remediate function
        kwargs = { "stdout": self.mock_subprocess.PIPE,
                   "stderr": self.mock_subprocess.PIPE,
                   }

        for arg in args:
            self.assertIn(arg, self.mock_subprocess.Popen.call_args[0][0])
            self.mock_subprocess.Popen.call_args[0][0].remove(arg)

        # nothing else should have been passed
        self.assertEqual(self.mock_subprocess.Popen.call_args[0][0], [])

        for (key, val) in kwargs.iteritems():
            self.assertEqual(kwargs[key],
                             self.mock_subprocess.Popen.call_args[1].pop(key))

        # plus the preexec_fn kwarg should have been passed
        self.assertIn("preexec_fn", self.mock_subprocess.Popen.call_args[1])

    def run_oscap_remediate_dont_create_dir_test(self):
        self.mock_os.path.isdir.return_value = True
        self.run_oscap_remediate("myprofile", "my_ds.xml")

        self.assertTrue(self.mock_os.path.isdir.called)
        self.assertFalse(self.mock_os.makedirs.called)

    def run_oscap_remediate_create_dir_test(self):
        self.mock_os.path.isdir.return_value = False
        self.run_oscap_remediate("myprofile", "my_ds.xml")

        self.assertTrue(self.mock_os.path.isdir.called)
        self.assertTrue(self.mock_os.makedirs.called)
        self.mock_os.makedirs.assert_called_with_args(os.path.dirname(
                                                      common.RESULTS_PATH))

    def run_oscap_remediate_create_chroot_dir_test(self):
        self.mock_os.path.isdir.return_value = False
        self.run_oscap_remediate("myprofile", "my_ds.xml", chroot="/mnt/test")

        self.assertTrue(self.mock_os.path.isdir.called)
        self.assertTrue(self.mock_os.makedirs.called)
        chroot_dir = "/mnt/test" + common.RESULTS_PATH
        self.mock_os.makedirs.assert_called_with_args(chroot_dir)

if __name__ == "__main__":
    unittest.main()
