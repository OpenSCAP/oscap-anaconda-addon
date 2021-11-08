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


from unittest import mock
import os
from collections import namedtuple

import pytest

from org_fedora_oscap import utils


@pytest.fixture()
def mock_os():
    mock_os = mock.Mock()
    mock_os.makedirs = mock.Mock()
    mock_os.path = mock.Mock()
    mock_os.path.isdir = mock.Mock()
    return mock_os


def mock_utils_os(mock_os, monkeypatch):
    utils_module_symbols = utils.__dict__

    monkeypatch.setitem(utils_module_symbols, "os", mock_os)


def test_existing_dir(mock_os, monkeypatch):
    mock_utils_os(mock_os, monkeypatch)
    mock_os.path.isdir.return_value = True

    utils.ensure_dir_exists("/tmp/test_dir")

    mock_os.path.isdir.assert_called_with("/tmp/test_dir")
    assert not mock_os.makedirs.called


def test_nonexisting_dir(mock_os, monkeypatch):
    mock_utils_os(mock_os, monkeypatch)
    mock_os.path.isdir.return_value = False

    utils.ensure_dir_exists("/tmp/test_dir")

    mock_os.path.isdir.assert_called_with("/tmp/test_dir")
    mock_os.makedirs.assert_called_with("/tmp/test_dir")


def test_no_dir(mock_os, monkeypatch):
    mock_utils_os(mock_os, monkeypatch)
    # shouldn't raise an exception
    utils.ensure_dir_exists("")


def test_relative_relative():
    assert utils.join_paths("foo", "blah") == "foo/blah"


def test_relative_absolute():
    assert utils.join_paths("foo", "/blah") == "foo/blah"


def test_absolute_relative():
    assert utils.join_paths("/foo", "blah") == "/foo/blah"


def test_absolute_absolute():
    assert utils.join_paths("/foo", "/blah") == "/foo/blah"


def test_dict():
    dct = {"a": 1, "b": 2}

    mapped_dct = utils.keep_type_map(str.upper, dct)
    assert list(mapped_dct.keys()) == ["A", "B"]
    assert isinstance(mapped_dct, dict)


def test_list():
    lst = [1, 2, 4, 5]

    mapped_lst = utils.keep_type_map(lambda x: x ** 2, lst)
    assert mapped_lst == [1, 4, 16, 25]
    assert isinstance(mapped_lst, list)


def test_tuple():
    tpl = (1, 2, 4, 5)

    mapped_tpl = utils.keep_type_map(lambda x: x ** 2, tpl)
    assert mapped_tpl == (1, 4, 16, 25)
    assert isinstance(mapped_tpl, tuple)


def test_namedtuple():
    NT = namedtuple("TestingNT", ["a", "b"])
    ntpl = NT(2, 4)

    mapped_tpl = utils.keep_type_map(lambda x: x ** 2, ntpl)
    assert mapped_tpl == NT(4, 16)
    assert isinstance(mapped_tpl, tuple)
    assert isinstance(mapped_tpl, NT)


def test_set():
    st = {1, 2, 4, 5}

    mapped_st = utils.keep_type_map(lambda x: x ** 2, st)
    assert mapped_st == {1, 4, 16, 25}
    assert isinstance(mapped_st, set)


def test_str():
    stri = "abcd"

    mapped_stri = utils.keep_type_map(lambda c: chr((ord(c) + 2) % 256), stri)
    assert mapped_stri == "cdef"
    assert isinstance(mapped_stri, str)


def test_gen():
    generator = (el for el in (1, 2, 4, 5))

    mapped_generator = utils.keep_type_map(lambda x: x ** 2, generator)
    assert tuple(mapped_generator) == (1, 4, 16, 25)

    # any better test for this?
    assert "__next__" in dir(mapped_generator)


def test_hash():
    file_hash = '87fcda7d9e7a22412e95779e2f8e70f929106c7b27a94f5f8510553ebf4624a6'
    hash_obj = utils.get_hashing_algorithm(file_hash)
    assert hash_obj.name == "sha256"

    filepath = os.path.join(os.path.dirname(__file__), 'data', 'file')
    computed_hash = utils.get_file_fingerprint(filepath, hash_obj)

    assert file_hash == computed_hash
