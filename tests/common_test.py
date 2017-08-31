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

        self.mock_utils = mock.Mock()
        self.mock_utils.ensure_dir_exists = mock.Mock()

        self.run_oscap_remediate = common.run_oscap_remediate
        self.run_oscap_remediate.func_globals["subprocess"] = self.mock_subprocess
        self.run_oscap_remediate.func_globals["utils"] = self.mock_utils

    def run_oscap_remediate_profile_only_test(self):
        self.run_oscap_remediate("myprofile", "my_ds.xml")

        # check calls where done right
        args = ["oscap", "xccdf", "eval", "--remediate",
                "--results=%s" % common.RESULTS_PATH,
                "--report=%s" % common.REPORT_PATH,
                "--profile=myprofile",
                "my_ds.xml"]

        # it's impossible to check the preexec_func as it is an internal
        # function of the run_oscap_remediate function
        kwargs = {"stdout": self.mock_subprocess.PIPE,
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
                "--results=%s" % common.RESULTS_PATH,
                "--report=%s" % common.REPORT_PATH,
                "--profile=myprofile",
                "--datastream-id=my_ds_id", "my_ds.xml"]

        # it's impossible to check the preexec_func as it is an internal
        # function of the run_oscap_remediate function
        kwargs = {"stdout": self.mock_subprocess.PIPE,
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
                "--results=%s" % common.RESULTS_PATH,
                "--report=%s" % common.REPORT_PATH,
                "--profile=myprofile",
                "--datastream-id=my_ds_id", "--xccdf-id=my_xccdf_id",
                "my_ds.xml"]

        # it's impossible to check the preexec_func as it is an internal
        # function of the run_oscap_remediate function
        kwargs = {"stdout": self.mock_subprocess.PIPE,
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

    def run_oscap_remediate_create_dir_test(self):
        self.run_oscap_remediate("myprofile", "my_ds.xml")

        self.mock_utils.ensure_dir_exists.assert_called_with(
            os.path.dirname(common.RESULTS_PATH))

    def run_oscap_remediate_create_chroot_dir_test(self):
        self.run_oscap_remediate("myprofile", "my_ds.xml", chroot="/mnt/test")

        chroot_dir = "/mnt/test" + os.path.dirname(common.RESULTS_PATH)
        self.mock_utils.ensure_dir_exists.assert_called_with(chroot_dir)


if __name__ == "__main__":
    unittest.main()
