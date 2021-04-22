#
# Copyright (C) 2020  Red Hat, Inc.
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
from dasbus.structure import DBusData
from dasbus.typing import *  # pylint: disable=wildcard-import

__all__ = ["PolicyData"]


class PolicyData(DBusData):
    """The security policy data."""

    def __init__(self):
        # values specifying the content
        self._content_type = ""
        self._content_url = ""
        self._datastream_id = ""
        self._xccdf_id = ""
        self._profile_id = ""
        self._content_path = ""
        self._cpe_path = ""
        self._tailoring_path = ""
        self._fingerprint = ""
        self._certificates = ""

    @property
    def content_type(self) -> Str:
        """Type of the security content.

        If the content type is scap-security-guide, the add-on
        will use content provided by the scap-security-guide.
        All other attributes except profile will have no effect.

        Supported values:

            datastream
            archive
            rpm
            scap-security-guide

        :return: a string
        """
        return self._content_type

    @content_type.setter
    def content_type(self, value: Str):
        self._content_type = value

    @property
    def content_url(self) -> Str:
        """Location of the security content.

         So far only http, https, and ftp URLs are supported.

        :return: an URL
        """
        return self._content_url

    @content_url.setter
    def content_url(self, value: Str):
        self._content_url = value

    @property
    def datastream_id(self) -> Str:
        """ID of the data stream.

        It is an ID of the data stream from a datastream
        collection referenced by the content url. Used only
        if the content type is datastream.

        :return: a string
        """
        return self._datastream_id

    @datastream_id.setter
    def datastream_id(self, value: Str):
        self._datastream_id = value

    @property
    def xccdf_id(self) -> Str:
        """ID of the benchmark that should be used.

        :return: a string
        """
        return self._xccdf_id

    @xccdf_id.setter
    def xccdf_id(self, value: Str):
        self._xccdf_id = value

    @property
    def profile_id(self) -> Str:
        """ID of the profile that should be applied.

        Use 'default' if the default profile should be used.

        :return: a string
        """
        return self._profile_id

    @profile_id.setter
    def profile_id(self, value: Str):
        self._profile_id = value

    @property
    def content_path(self) -> Str:
        """Path to the datastream or the XCCDF file which should be used.

        :return: a relative path in the archive
        """
        return self._content_path

    @content_path.setter
    def content_path(self, value: Str):
        self._content_path = value

    @property
    def cpe_path(self) -> Str:
        """Path to the datastream or the XCCDF file that should be used.

        :return: a relative path in the archive
        """
        return self._cpe_path

    @cpe_path.setter
    def cpe_path(self, value: Str):
        self._cpe_path = value

    @property
    def tailoring_path(self) -> Str:
        """Path of the tailoring file that should be used.

        :return: a relative path in the archive
        """
        return self._tailoring_path

    @tailoring_path.setter
    def tailoring_path(self, value: Str):
        self._tailoring_path = value

    @property
    def fingerprint(self) -> Str:
        """Checksum of the security content.

        It is an MD5, SHA1 or SHA2 fingerprint/hash/checksum
        of the content referred by the content url.

        :return: a string
        """
        return self._fingerprint

    @fingerprint.setter
    def fingerprint(self, value: Str):
        self._fingerprint = value

    @property
    def certificates(self) -> Str:
        """Path to a PEM file with CA certificate chain.

        :return: a path
        """
        return self._certificates

    @certificates.setter
    def certificates(self, value: Str):
        self._certificates = value
