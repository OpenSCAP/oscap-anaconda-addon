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
from collections import namedtuple

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

    def tearDown(self):
        # restore the original os module for the utils module
        utils.ensure_dir_exists.func_globals["os"] = os


class JoinPathsTest(unittest.TestCase):
    """Tests for the join_paths function."""

    def relative_relative_test(self):
        self.assertEqual(utils.join_paths("foo", "blah"), "foo/blah")

    def relative_absolute_test(self):
        self.assertEqual(utils.join_paths("foo", "/blah"), "foo/blah")

    def absolute_relative_test(self):
        self.assertEqual(utils.join_paths("/foo", "blah"), "/foo/blah")

    def absolute_absolute_test(self):
        self.assertEqual(utils.join_paths("/foo", "/blah"), "/foo/blah")


class KeepTypeMapTest(unittest.TestCase):
    """Tests for the keep_type_map function."""

    def dict_test(self):
        dct = {"a": 1, "b": 2}

        mapped_dct = utils.keep_type_map(str.upper, dct)
        self.assertEqual(mapped_dct.keys(), ["A", "B"])
        self.assertIsInstance(mapped_dct, dict)

    def list_test(self):
        lst = [1, 2, 4, 5]
        func = lambda x: x**2

        mapped_lst = utils.keep_type_map(func, lst)
        self.assertEqual(mapped_lst, [1, 4, 16, 25])
        self.assertIsInstance(mapped_lst, list)

    def tuple_test(self):
        tpl = (1, 2, 4, 5)
        func = lambda x: x**2

        mapped_tpl = utils.keep_type_map(func, tpl)
        self.assertEqual(mapped_tpl, (1, 4, 16, 25))
        self.assertIsInstance(mapped_tpl, tuple)

    def namedtuple_test(self):
        NT = namedtuple("TestingNT", ["a", "b"])
        ntpl = NT(2, 4)
        func = lambda x: x**2

        mapped_tpl = utils.keep_type_map(func, ntpl)
        self.assertEqual(mapped_tpl, NT(4, 16))
        self.assertIsInstance(mapped_tpl, tuple)
        self.assertIsInstance(mapped_tpl, NT)

    def set_test(self):
        st = {1, 2, 4, 5}
        func = lambda x: x**2

        mapped_st = utils.keep_type_map(func, st)
        self.assertEqual(mapped_st, {1, 4, 16, 25})
        self.assertIsInstance(mapped_st, set)

    def str_test(self):
        stri = "abcd"
        func = lambda c: chr((ord(c) + 2) % 256)

        mapped_stri = utils.keep_type_map(func, stri)
        self.assertEqual(mapped_stri, "cdef")
        self.assertIsInstance(mapped_stri, str)

    def gen_test(self):
        gen = (it for it in [1, 2, 4, 5])
        func = lambda x: x**2

        mapped_gen = utils.keep_type_map(func, gen)
        self.assertEqual(tuple(mapped_gen), tuple([1, 4, 16, 25]))

        # any better test for this?
        self.assertIn("next", dir(mapped_gen))
