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

"""Module with tests for the data_fetch module"""

import unittest
from org_fedora_oscap import data_fetch

class HeadersHandlingTest(unittest.TestCase):
    """Test if the headers are handled correctly (thrown away)"""

    def headers_only_incomplete_test(self):
        data = "header1: value\r\nheader2: value\r\n\r\n"
        done, rest = data_fetch._throw_away_headers(data)
        self.assertTrue(done)
        self.assertIs(rest, "")

    def headers_only_complete_test(self):
        data = "header1: value\r\nheader2: value\r\n"
        done, rest = data_fetch._throw_away_headers(data)
        self.assertFalse(done)
        self.assertIs(rest, "")

    def headers_and_data_test(self):
        data = "Begining of the data"
        headers_data = "header1: value\r\nheader2: value\r\n\r\n%s" % data
        done, rest = data_fetch._throw_away_headers(headers_data)
        self.assertTrue(done)
        self.assertEqual(rest, data)

