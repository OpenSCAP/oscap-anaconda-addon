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

"""Module with various utility functions used by the addon."""

import os
import os.path
import shutil
import glob
import hashlib


def ensure_dir_exists(dirpath):
    """
    Checks if a given directory exists and if not, it creates the directory as
    well as all the nonexisting directories in its path.

    :param dirpath: path to the directory to be checked/created
    :type dirpath: str

    """

    if not dirpath:
        # nothing can be done for an empty string
        return

    if not os.path.isdir(dirpath):
        os.makedirs(dirpath)


def universal_copy(src, dst):
    """
    Function that copies the files or directories specified by the src argument
    to the destination given by the dst argument. It should follow the same
    rules as the standard 'cp' utility.

    :param src: source to copy -- may be a glob, file path or a directory path
    :type src: str
    :param dst: destination to copy to
    :type src: str

    """

    if glob.has_magic(src):
        # src is a glob
        sources = glob.glob(src)
    else:
        # not a glob
        sources = [src]

    for item in sources:
        if os.path.isdir(item):
            if os.path.isdir(dst):
                item = item.rstrip("/")
                dirname = item.rsplit("/", 1)[-1]
                shutil.copytree(item, join_paths(dst, dirname))
            else:
                shutil.copytree(item, dst)
        else:
            shutil.copy2(item, dst)


def keep_type_map(func, iterable):
    """
    Function that maps the given function to items in the given iterable
    keeping the type of the iterable.

    :param func: function to be mapped on the items in the iterable
    :type func: in_item -> out_item
    :param iterable: iterable providing the items the function should be mapped
                     on
    :type iterable: iterable
    :return: iterable providing items produced by the function mapped on the
             input items
    :rtype: the same type as input iterable or generator if the iterable is not
            of any basic Python types

    """

    if isinstance(iterable, dict):
        return dict((func(key), iterable[key]) for key in iterable)

    items_gen = (func(item) for item in iterable)
    if isinstance(iterable, list):
        return list(items_gen)
    elif isinstance(iterable, tuple):
        if iterable.__class__ is tuple:
            return tuple(items_gen)
        else:
            return iterable.__class__(*items_gen)
    elif isinstance(iterable, set):
        return set(items_gen)
    elif isinstance(iterable, str):
        return "".join(items_gen)
    else:
        return items_gen


def join_paths(path1, path2):
    """
    Joins two paths as one would expect -- i.e. just like the os.path.join
    function except for doing crazy things when the second argument is an
    absolute path.

    :param path1: first path
    :type path1: str
    :param path2: second path
    :type path2: str
    :return: path1 and path2 joined with the file separator
    :rtype: str

    """

    # os.path.normpath doesn't squash two starting slashes
    path1.replace("//", "/")

    return os.path.normpath(path1 + os.path.sep + path2)


def get_hashing_algorithm(fingerprint):
    """
    Get hashing algorithm for the given fingerprint or None if fingerprint of
    unsupported length is given.

    :param fingerprint: hexa fingerprint to get the hashing algorithm for
    :type fingerprint: hexadecimal str
    :return: one of the hashlib.* hash objects
    :rtype: hashlib.HASH object

    """

    hashes = (hashlib.md5(), hashlib.sha1(), hashlib.sha224(),
              hashlib.sha256(), hashlib.sha384(), hashlib.sha512())

    if len(fingerprint) % 2 == 1:
        return None

    num_bytes = len(fingerprint) / 2

    for hash_obj in hashes:
        # pylint: disable-msg=E1103
        if hash_obj.digest_size == num_bytes:
            return hash_obj

    return None


def get_file_fingerprint(fpath, hash_obj):
    """
    Get fingerprint of the given file with the given hashing algorithm.

    :param fpath: path to the file to get fingerprint for
    :type fpath: str
    :param hash_obj: hashing algorithm to get fingerprint with
    :type hash_obj: hashlib.HASH
    :return: fingerprint of the given file with the given algorithm
    :rtype: hexadecimal str

    """

    with open(fpath, "r") as fobj:
        bsize = 4*1024
        # process file as 4 KB blocks
        buf = fobj.read(bsize)
        while buf:
            hash_obj.update(buf)
            buf = fobj.read(bsize)

    return hash_obj.hexdigest()
