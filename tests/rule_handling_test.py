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
import mock

from org_fedora_oscap import rule_handling, common


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
        self.rule_data.new_rule("bootloader --passwd")

        # both partitions should appear in self.rule_data._part_rules
        self.assertIn("/tmp", self.rule_data._part_rules)
        self.assertIn("/var/log", self.rule_data._part_rules)

        # mount options should be parsed
        self.assertIn("nodev",
                      self.rule_data._part_rules["/tmp"]._mount_options)
        self.assertIn("noauto",
                      self.rule_data._part_rules["/tmp"]._mount_options)

        # no mount options for /var/log
        self.assertEqual(self.rule_data._part_rules["/var/log"]._mount_options,
                         [])

        # minimal password length should be parsed and stored correctly
        self.assertEqual(self.rule_data._passwd_rules._minlen, 14)

        # packages should be parsed correctly
        self.assertIn("iptables", self.rule_data._package_rules._add_pkgs)
        self.assertIn("firewalld", self.rule_data._package_rules._add_pkgs)
        self.assertIn("telnet", self.rule_data._package_rules._remove_pkgs)
        self.assertIn("rlogin", self.rule_data._package_rules._remove_pkgs)
        self.assertIn("sshd", self.rule_data._package_rules._remove_pkgs)

        # bootloader should require password
        self.assertTrue(self.rule_data._bootloader_rules._require_password)

    def quoted_opt_values_test(self):
        self.rule_data.new_rule('part /tmp --mountoptions="nodev,noauto"')

        self.assertIn("nodev",
                      self.rule_data._part_rules["/tmp"]._mount_options)
        self.assertIn("noauto",
                      self.rule_data._part_rules["/tmp"]._mount_options)
        self.assertNotIn('"',
                         self.rule_data._part_rules["/tmp"]._mount_options)

    def real_output_test(self):
        output = """
      part /tmp

      part /tmp --mountoptions=nodev
    """
        for line in output.splitlines():
            self.rule_data.new_rule(line)

        self.assertIn("/tmp", self.rule_data._part_rules)
        self.assertIn("nodev",
                      self.rule_data._part_rules["/tmp"]._mount_options)

        # should be stripped and merged
        self.assertEqual(str(self.rule_data._part_rules),
                         "part /tmp --mountoptions=nodev")


class RuleEvaluationTest(unittest.TestCase):
    """Test if the rule evaluation works properly."""

    def setUp(self):
        self.rule_data = rule_handling.RuleData()
        self.ksdata_mock = mock.Mock()
        self.storage_mock = mock.Mock()

    def existing_part_must_exist_rules_test(self):
        for rule in ["part /tmp", "part /"]:
            self.rule_data.new_rule(rule)

        tmp_part_mock = mock.Mock()
        tmp_part_mock.format.options = "defaults"
        root_part_mock = mock.Mock()
        root_part_mock.format.options = "defaults"

        self.storage_mock.mountpoints = {"/tmp": tmp_part_mock,
                                         "/": root_part_mock,
                                         }

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # partitions exist --> no errors, warnings or additional info
        self.assertEqual(messages, [])

        # no additional mount options specified
        self.assertEqual(tmp_part_mock.format.options, "defaults")
        self.assertEqual(root_part_mock.format.options, "defaults")

    def nonexisting_part_must_exist_test(self):
        for rule in ["part /tmp", "part /"]:
            self.rule_data.new_rule(rule)

        tmp_part_mock = mock.Mock()
        tmp_part_mock.format.options = "defaults"

        self.storage_mock.mountpoints = {"/tmp": tmp_part_mock,
                                         }

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # / mount point missing --> one error
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].type, common.MESSAGE_TYPE_FATAL)

        # error has to mention the mount point
        self.assertIn("/", messages[0].text)

    def add_mount_options_test(self):
        for rule in ["part /tmp --mountoptions=defaults,nodev",
                     "part / --mountoptions=noauto"]:
            self.rule_data.new_rule(rule)

        tmp_part_mock = mock.Mock()
        tmp_part_mock.format.options = "defaults"
        root_part_mock = mock.Mock()
        root_part_mock.format.options = "defaults"

        self.storage_mock.mountpoints = {"/tmp": tmp_part_mock,
                                         "/": root_part_mock,
                                         }

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # two mount options added --> two info messages
        self.assertEqual(len(messages), 2)
        self.assertTrue(all(message.type == common.MESSAGE_TYPE_INFO
                            for message in messages))

        # newly added mount options should be mentioned in the messages
        # together with their mount points
        nodev_found = False
        noauto_found = False

        for message in messages:
            if "'nodev'" in message.text:
                self.assertIn("/tmp", message.text)
                nodev_found = True
            elif "'noauto'" in message.text:
                self.assertIn("/", message.text)
                noauto_found = True

        self.assertTrue(all([nodev_found, noauto_found]))
        self.assertEqual(self.storage_mock.mountpoints["/tmp"].format.options,
                         "defaults,nodev")
        self.assertEqual(self.storage_mock.mountpoints["/"].format.options,
                         "defaults,noauto")

    def add_mount_options_no_duplicates_test(self):
        for rule in ["part /tmp --mountoptions=defaults,nodev",
                     "part / --mountoptions=noauto"]:
            self.rule_data.new_rule(rule)

        tmp_part_mock = mock.Mock()
        tmp_part_mock.format.options = "defaults"
        root_part_mock = mock.Mock()
        root_part_mock.format.options = "defaults"

        self.storage_mock.mountpoints = {"/tmp": tmp_part_mock,
                                         "/": root_part_mock,
                                         }

        # evaluate twice, so that duplicates could possible by created
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # two mount options added --> two info messages
        self.assertEqual(len(messages), 2)
        self.assertTrue(all(message.type == common.MESSAGE_TYPE_INFO
                            for message in messages))

        # newly added mount options should be mentioned in the messages
        # together with their mount points
        nodev_found = False
        noauto_found = False

        for message in messages:
            if "'nodev'" in message.text:
                self.assertIn("/tmp", message.text)
                nodev_found = True
            elif "'noauto'" in message.text:
                self.assertIn("/", message.text)
                noauto_found = True

        self.assertTrue(all([nodev_found, noauto_found]))

        # no duplicates should be added (each new mount option only once)
        self.assertEqual(self.storage_mock.mountpoints["/tmp"].format.options,
                         "defaults,nodev")
        self.assertEqual(self.storage_mock.mountpoints["/"].format.options,
                         "defaults,noauto")

    def add_mount_options_report_only_test(self):
        for rule in ["part /tmp --mountoptions=nodev",
                     "part / --mountoptions=noauto"]:
            self.rule_data.new_rule(rule)

        tmp_part_mock = mock.Mock()
        tmp_part_mock.format.options = "defaults"
        root_part_mock = mock.Mock()
        root_part_mock.format.options = "defaults"

        self.storage_mock.mountpoints = {"/tmp": tmp_part_mock,
                                         "/": root_part_mock,
                                         }

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock,
                                             report_only=True)

        # two mount options added --> two info messages
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].type, common.MESSAGE_TYPE_INFO)
        self.assertEqual(messages[1].type, common.MESSAGE_TYPE_INFO)

        # newly added mount options should be mentioned in the messages
        # together with their mount points
        nodev_found = False
        noauto_found = False

        for message in messages:
            if "'nodev'" in message.text:
                self.assertIn("/tmp", message.text)
                nodev_found = True
            elif "'noauto'" in message.text:
                self.assertIn("/", message.text)
                noauto_found = True

        self.assertTrue(all([nodev_found, noauto_found]))

        # no changes should be made
        self.assertEqual(self.storage_mock.mountpoints["/tmp"].format.options,
                         "defaults")
        self.assertEqual(self.storage_mock.mountpoints["/"].format.options,
                         "defaults")

    def add_mount_option_prefix_test(self):
        for rule in ["part /tmp --mountoptions=nodev",
                     "part / --mountoptions=noauto"]:
            self.rule_data.new_rule(rule)

        tmp_part_mock = mock.Mock()
        tmp_part_mock.format.options = "defaults,nodevice"
        root_part_mock = mock.Mock()
        root_part_mock.format.options = "defaults"

        self.storage_mock.mountpoints = {"/tmp": tmp_part_mock,
                                         "/": root_part_mock,
                                         }

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # two mount options added (even though it is a prefix of another one)
        #   --> two info messages
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].type, common.MESSAGE_TYPE_INFO)
        self.assertEqual(messages[1].type, common.MESSAGE_TYPE_INFO)

        # the option should be added even though it is a prefix of another one
        self.assertEqual(self.storage_mock.mountpoints["/tmp"].format.options,
                         "defaults,nodevice,nodev")

    def add_mount_options_nonexisting_part_test(self):
        for rule in ["part /tmp --mountoptions=nodev",
                     "part / --mountoptions=noauto"]:
            self.rule_data.new_rule(rule)

        tmp_part_mock = mock.Mock()
        tmp_part_mock.format.options = "defaults"
        root_part_mock = mock.Mock()
        root_part_mock.format.options = "defaults"

        self.storage_mock.mountpoints = {"/": root_part_mock,
                                         }

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # one mount option added, one mount point missing (mount options
        # cannot be added) --> one info, one error
        self.assertEqual(len(messages), 2)
        self.assertTrue(any(message.type == common.MESSAGE_TYPE_INFO
                            for message in messages))
        self.assertTrue(any(message.type == common.MESSAGE_TYPE_FATAL
                            for message in messages))

        # the info message should report mount options added to the existing
        # mount point, the error message shoud contain the missing mount point
        # and not the mount option
        for message in messages:
            if message.type == common.MESSAGE_TYPE_INFO:
                self.assertIn("/", message.text)
                self.assertIn("'noauto'", message.text)
            elif message.type == common.MESSAGE_TYPE_FATAL:
                self.assertIn("/tmp", message.text)
                self.assertNotIn("'nodev'", message.text)

    def passwd_minlen_no_passwd_test(self):
        self.rule_data.new_rule("passwd --minlen=8")

        self.ksdata_mock.rootpw.password = ""
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # minimal password length required --> one warning
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].type, common.MESSAGE_TYPE_WARNING)

        # warning has to mention the length
        self.assertIn("8", messages[0].text)

    def passwd_minlen_short_passwd_test(self):
        self.rule_data.new_rule("passwd --minlen=8")

        self.ksdata_mock.rootpw.password = "aaaa"
        self.ksdata_mock.rootpw.isCrypted = False
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # minimal password length greater than actual length --> one warning
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].type, common.MESSAGE_TYPE_FATAL)

        # warning has to mention the length
        self.assertIn("8", messages[0].text)

        # warning should mention that something is wrong with the old password
        self.assertIn("is", messages[0].text)

        # doing changes --> password should not be cleared
        self.assertEqual(self.ksdata_mock.rootpw.password, "aaaa")

    def passwd_minlen_short_passwd_report_only_test(self):
        self.rule_data.new_rule("passwd --minlen=8")

        self.ksdata_mock.rootpw.password = "aaaa"
        self.ksdata_mock.rootpw.isCrypted = False

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock,
                                             report_only=True)

        # minimal password length greater than actual length --> one warning
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].type, common.MESSAGE_TYPE_FATAL)

        # warning has to mention the length
        self.assertIn("8", messages[0].text)

        # report only --> password shouldn't be cleared
        self.assertEqual(self.ksdata_mock.rootpw.password, "aaaa")

    def passwd_minlen_crypted_passwd_test(self):
        self.rule_data.new_rule("passwd --minlen=8")

        self.ksdata_mock.rootpw.password = "aaaa"
        self.ksdata_mock.rootpw.isCrypted = True

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # minimal password length greater than actual length --> one warning
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].type, common.MESSAGE_TYPE_WARNING)

        # warning has to mention that the password cannot be checked
        self.assertIn("cannot check", messages[0].text)

    def passwd_minlen_good_passwd_test(self):
        self.rule_data.new_rule("passwd --minlen=8")

        self.ksdata_mock.rootpw.password = "aaaaaaaaaaaaaaaaa"
        self.ksdata_mock.rootpw.isCrypted = False

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # minimal password length less than actual length --> no warning
        self.assertEqual(messages, [])

    def passwd_minlen_report_only_not_ignored_test(self):
        self.rule_data.new_rule("passwd --minlen=8")
        self.ksdata_mock.rootpw.password = "aaaaaaaaaaaaaaaaa"
        self.ksdata_mock.rootpw.isCrypted = False

        # Mock pw_policy returned by anaconda.pwpolicy.get_policy()
        pw_policy_mock = mock.Mock()
        pw_policy_mock.minlen = 6
        pw_policy_mock.strict = False
        self.ksdata_mock.anaconda.pwpolicy.get_policy.return_value = \
            pw_policy_mock

        # call eval_rules with report_only=False
        # should set password minimal length to 8
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock,
                                             report_only=False)
        # Password Policy changed --> no warnings
        self.assertEqual(messages, [])
        self.assertEqual(self.rule_data._passwd_rules._orig_minlen, 6)
        self.assertEqual(self.rule_data._passwd_rules._orig_strict, False)
        self.assertEqual(pw_policy_mock.minlen, 8)
        self.assertEqual(pw_policy_mock.strict, True)
        self.assertEqual(self.rule_data._passwd_rules._minlen, 8)

        # call of eval_rules with report_only=True
        # should not change anything
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock,
                                             report_only=True)
        # Password Policy stayed the same --> no warnings
        self.assertEqual(messages, [])

        self.assertEqual(self.rule_data._passwd_rules._orig_minlen, 6)
        self.assertEqual(self.rule_data._passwd_rules._orig_strict, False)
        self.assertEqual(pw_policy_mock.minlen, 8)
        self.assertEqual(pw_policy_mock.strict, True)
        self.assertEqual(self.rule_data._passwd_rules._minlen, 8)

    def package_rules_test(self):
        self.rule_data.new_rule("package --add=firewalld --remove=telnet "
                                "--add=iptables --add=vim")

        self.ksdata_mock.packages.packageList = ["vim"]
        self.ksdata_mock.packages.excludedList = []

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # one info message for each (really) added/removed package
        self.assertEqual(len(messages), 3)
        self.assertTrue(all(message.type == common.MESSAGE_TYPE_INFO
                            for message in messages))

        # all packages should appear in the messages
        must_see = ["firewalld", "telnet", "iptables"]
        for message in messages:
            if "'firewalld'" in message.text:
                must_see.remove("firewalld")
            elif "'telnet'" in message.text:
                must_see.remove("telnet")
            elif "'iptables'":
                must_see.remove("iptables")

        self.assertEqual(must_see, [])
        self.assertEqual(set(self.ksdata_mock.packages.packageList),
                         {"firewalld", "iptables", "vim"})
        self.assertEqual(set(self.ksdata_mock.packages.excludedList),
                         {"telnet"})

    def package_rules_report_only_test(self):
        self.rule_data.new_rule("package --add=firewalld --remove=telnet "
                                "--add=iptables")

        self.ksdata_mock.packages.packageList = []
        self.ksdata_mock.packages.excludedList = []

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock,
                                             report_only=True)

        # one info message for each added/removed package
        self.assertEqual(len(messages), 3)
        self.assertTrue(all(message.type == common.MESSAGE_TYPE_INFO
                            for message in messages))

        # all packages should appear in the messages
        must_see = ["firewalld", "telnet", "iptables"]
        for message in messages:
            if "'firewalld'" in message.text:
                must_see.remove("firewalld")
            elif "'telnet'" in message.text:
                must_see.remove("telnet")
            elif "'iptables'":
                must_see.remove("iptables")

        self.assertEqual(must_see, [])

        # report_only --> no packages should be added or excluded
        self.assertEqual(self.ksdata_mock.packages.packageList, [])
        self.assertEqual(self.ksdata_mock.packages.excludedList, [])

    def bootloader_passwd_not_set_test(self):
        self.rule_data.new_rule("bootloader --passwd")

        self.storage_mock.bootloader.password = None

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # bootloader password not set --> one warning
        self.assertEqual(len(messages), 1)
        self.assertTrue(messages[0].type == common.MESSAGE_TYPE_WARNING)

    def bootloader_passwd_set_test(self):
        self.rule_data.new_rule("bootloader --passwd")

        self.storage_mock.bootloader.password = "aaaaa"

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # bootloader password set --> no warnings
        self.assertEqual(messages, [])

    def various_rules_test(self):
        for rule in ["part /tmp", "part /", "passwd --minlen=14",
                     "package --add=firewalld", ]:
            self.rule_data.new_rule(rule)

        self.storage_mock.mountpoints = dict()
        self.ksdata_mock.packages.packageList = []
        self.ksdata_mock.packages.excludedList = []

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # four rules, all fail --> four messages
        self.assertEqual(len(messages), 4)


class RevertingTest(unittest.TestCase):
    """Test for reverting changes done by the rule evaluation."""

    def setUp(self):
        self.rule_data = rule_handling.RuleData()
        self.ksdata_mock = mock.Mock()
        self.storage_mock = mock.Mock()

    def revert_mount_options_nonexistent_test(self):
        self.rule_data.new_rule("part /tmp --mountoptions=nodev")
        self.storage_mock.mountpoints = dict()

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # mount point doesn't exist -> one message, nothing done
        self.assertEqual(len(messages), 1)
        self.assertEqual(self.storage_mock.mountpoints, dict())

        # mount point doesn't exist -> shouldn't do anything
        self.rule_data.revert_changes(self.ksdata_mock, self.storage_mock)
        self.assertEqual(self.storage_mock.mountpoints, dict())

    def revert_mount_options_test(self):
        self.rule_data.new_rule("part /tmp --mountoptions=nodev")
        self.storage_mock.mountpoints = dict()
        self.storage_mock.mountpoints["/tmp"] = mock.Mock()
        self.storage_mock.mountpoints["/tmp"].format.options = "defaults"

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # mount option added --> one message
        self.assertEqual(len(messages), 1)

        # "nodev" option should be added
        self.assertEqual(self.storage_mock.mountpoints["/tmp"].format.options,
                         "defaults,nodev")

        self.rule_data.revert_changes(self.ksdata_mock, self.storage_mock)

        # should be reverted to the original value
        self.assertEqual(self.storage_mock.mountpoints["/tmp"].format.options,
                         "defaults")

        # another cycle of the same #
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # mount option added --> one message
        self.assertEqual(len(messages), 1)

        # "nodev" option should be added
        self.assertEqual(self.storage_mock.mountpoints["/tmp"].format.options,
                         "defaults,nodev")

        self.rule_data.revert_changes(self.ksdata_mock, self.storage_mock)

        # should be reverted to the original value
        self.assertEqual(self.storage_mock.mountpoints["/tmp"].format.options,
                         "defaults")

    def revert_password_policy_changes_test(self):
        # FIXME: Add password policy changes to this test. It only checks
        # password length right now outside of policy changes.
        self.rule_data.new_rule("passwd --minlen=8")

        self.ksdata_mock.rootpw.password = "aaaa"
        self.ksdata_mock.rootpw.isCrypted = False
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # password error --> one message
        self.assertEqual(len(messages), 1)
        self.assertEqual(self.ksdata_mock.rootpw.password, "aaaa")
        self.assertTrue(self.ksdata_mock.rootpw.seen)

        self.rule_data.revert_changes(self.ksdata_mock, self.storage_mock)

        # with long enough password this time #
        self.ksdata_mock.rootpw.password = "aaaaaaaaaaaaa"

        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # long enough password
        # entered --> no message
        self.assertEqual(messages, [])

    def revert_package_rules_test(self):
        self.rule_data.new_rule("package --add=firewalld --remove=telnet "
                                "--add=iptables --add=vim")

        self.ksdata_mock.packages.packageList = ["vim"]
        self.ksdata_mock.packages.excludedList = []

        # run twice --> nothing should be different in the second run
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # one info message for each added/removed package
        self.assertEqual(len(messages), 3)

        self.rule_data.revert_changes(self.ksdata_mock, self.storage_mock)

        # (only) added and excluded packages should have been removed from the
        # list
        self.assertEqual(self.ksdata_mock.packages.packageList, ["vim"])
        self.assertEqual(self.ksdata_mock.packages.excludedList, [])

        # now do the same again #
        messages = self.rule_data.eval_rules(self.ksdata_mock,
                                             self.storage_mock)

        # one info message for each added/removed package
        self.assertEqual(len(messages), 3)

        self.rule_data.revert_changes(self.ksdata_mock, self.storage_mock)

        # (only) added and excluded packages should have been removed from the
        # list
        self.assertEqual(self.ksdata_mock.packages.packageList, ["vim"])
        self.assertEqual(self.ksdata_mock.packages.excludedList, [])
