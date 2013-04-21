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

from org_fedora_oscap import utils

class EnsureDirExistTest(unittest.TestCase):
    """Tests for the ensure_dir_exists function."""

    def setUp(self):
        self.mock_os = mock.Mock()
        self.mock_os.makedirs = mock.Mock()
        self.mock_os.path = mock.Mock()
        self.mock_os.path.isdir = mock.Mock()

        self.ensure_dir_exists = utils.ensure_dir_exists
        self.ensure_dir_exists.func_globals["os"] = self.mock_os

    def existing_dir_test(self):
        self.mock_os.path.isdir.return_value = True

        self.ensure_dir_exists("/tmp/dir_test")

        self.mock_os.path.isdir.assert_called_with("/tmp/dir_test")
        self.assertFalse(self.mock_os.makedirs.called)

    def nonexisting_dir_test(self):
        self.mock_os.path.isdir.return_value = False

        self.ensure_dir_exists("/tmp/dir_test")

        self.mock_os.path.isdir.assert_called_with("/tmp/dir_test")
        self.mock_os.makedirs.assert_called_with("/tmp/dir_test")

    def no_dir_test(self):
        # shouldn't raise an exception
        self.ensure_dir_exists("")
