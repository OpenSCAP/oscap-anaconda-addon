#
# Copyright (C) 2017  Red Hat, Inc.
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
# Red Hat Author(s): Watson Sato <wsato@redhat.com>
#

"""Module with unit tests for the content_handling.py module"""

import unittest
import mock

from org_fedora_oscap import common
from org_fedora_oscap import content_handling as ch


class DataStreamHandlerTest(unittest.TestCase):
    """Test functionality of the DataStreanHandler'."""

    def setUp(self):
        self.ds_filepath = "../testing_files/testing_ds.xml"
        self.ds_ids = "scap_org.open-scap_datastream_tst"
        self.chk_first_id = "scap_org.open-scap_cref_first-xccdf.xml"
        self.chk_second_id = "scap_org.open-scap_cref_second-xccdf.xml"
        self.profile1_id = "xccdf_com.example_profile_my_profile"
        self.profile2_id = "xccdf_com.example_profile_my_profile2"
        self.profile3_id = "xccdf_com.example_profile_my_profile3"

    def init_invalid_file_path_test(self):
        with self.assertRaises(ch.DataStreamHandlingError) as e:
            ch.DataStreamHandler("testing_ds.xml")
        self.assertIn("Invalid file path", e.exception.message)

    def init_not_scap_content_test(self):
        with self.assertRaises(ch.DataStreamHandlingError) as e:
            ch.DataStreamHandler("../testing_files/testing_ks.cfg")
        self.assertIn("not a valid SCAP content file", e.exception.message)

    def init_xccdf_content_test(self):
        with self.assertRaises(ch.DataStreamHandlingError) as e:
            ch.DataStreamHandler("../testing_files/xccdf.xml")
        self.assertIn("not a data stream collection", e.exception.message)

    def get_data_streams_test(self):
        self.ds_handler = ch.DataStreamHandler(self.ds_filepath)
        ds_ids = self.ds_handler.get_data_streams()
        self.assertIn(self.ds_ids, ds_ids)

    def get_data_streams_checklists_test(self):
        expected_ids = {self.ds_ids: [self.chk_first_id, self.chk_second_id]}

        self.ds_handler = ch.DataStreamHandler(self.ds_filepath)
        ds_ids = self.ds_handler.get_data_streams_checklists()
        self.assertDictEqual(expected_ids, ds_ids)

    def get_checklists_test(self):
        expected_checklists = [self.chk_first_id, self.chk_second_id]

        self.ds_handler = ch.DataStreamHandler(self.ds_filepath)
        chk_ids = self.ds_handler.get_checklists(self.ds_ids)
        self.assertListEqual(expected_checklists, chk_ids)

    def get_checklists_invalid_test(self):
        self.ds_handler = ch.DataStreamHandler(self.ds_filepath)
        with self.assertRaises(ch.DataStreamHandlingError) as e:
            chk_ids = self.ds_handler.get_checklists("invalid.id")
        self.assertIn("Invalid data stream id given", e.exception.message)

    def get_profiles_test(self):
        self.ds_handler = ch.DataStreamHandler(self.ds_filepath)
        profile_ids = self.ds_handler.get_profiles(self.ds_ids,
                                                   self.chk_first_id)

        # When Benchmark doesn't contain Rules selected by default
        # the default Profile should not be present
        self.assertEqual(2, len(profile_ids))
        self.assertEqual(self.profile1_id, profile_ids[0].id)
        self.assertEqual(self.profile2_id, profile_ids[1].id)

    def get_profiles_with_default(self):
        self.ds_handler = ch.DataStreamHandler(self.ds_filepath)
        profile_ids = self.ds_handler.get_profiles(self.ds_ids,
                                                   self.chk_second_id)

        # When Benchmark contains Rules selected by default
        # the default Profile should be present
        self.assertEqual(2, len(profile_ids))
        self.assertEqual("default", profile_ids[0].id)
        self.assertEqual(self.profile3_id, profile_ids[1].id)
