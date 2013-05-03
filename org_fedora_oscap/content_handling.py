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

"""
Module with various classes for SCAP content processing and retrieving data from
it.

"""

from collections import namedtuple, OrderedDict
from openscap_api import OSCAP

class ContentHandlingError(Exception):
    """Exception class for errors related to SCAP content handling."""

    pass

class DataStreamHandlingError(ContentHandlingError):
    """Exception class for errors related to data stream handling."""

    pass

# namedtuple class (not a constant, pylint!) for info about a XCCDF profile
# pylint: disable-msg=C0103
ProfileInfo = namedtuple("ProfileInfo", ["id", "title", "description"])

def oscap_text_itr_get_text(itr):
    """
    Helper function for getting a text from the oscap_text_iterator.

    :param itr: oscap_text_iterator to get the text from
    :type itr: oscap_text_iterator
    :return: text gotten from the iterator
    :rtype: str

    """

    ret = ""
    while OSCAP.oscap_text_iterator_has_more(itr):
        text_item = OSCAP.oscap_text_iterator_next(itr)
        ret += OSCAP.oscap_text_get_text(text_item)

    return ret

class DataStreamHandler(object):
    """
    Class for handling data streams in the data stream collection and retrieving
    data from it. For example a list of data stream indices, checklists in a
    given data stream of profiles.

    """

    def __init__(self, dsc_file_path):
        """
        Constructor for the DataStreamHandler class.

        :param dsc_file_path: path to a file with a data stream collection
        :type dsc_file_path: str

        """

        # is used to speed up getting lists of profiles
        self._profiles_cache = dict()

        if not dsc_file_path:
            msg = "Invalid file path: '%s'" % dsc_file_path
            raise DataStreamHandlingError(msg)

        # create an XCCDF session for the file
        self._session = OSCAP.xccdf_session_new(dsc_file_path)

        if not OSCAP.xccdf_session_is_sds(self._session):
            msg = "'%s' is not a data stream collection" % dsc_file_path
            raise DataStreamHandlingError(msg)

        # dictionary holding the items gathered from DSC processing
        self._items = OrderedDict()

        # create an sds index for the content
        self._sds_idx = OSCAP.xccdf_session_get_sds_idx(self._session)

        # iterate over streams and get checklists from each stream
        streams_itr = OSCAP.ds_sds_index_get_streams(self._sds_idx)
        while OSCAP.ds_stream_index_iterator_has_more(streams_itr):
            stream_idx = OSCAP.ds_stream_index_iterator_next(streams_itr)

            # will be used to store the checklists for streams
            stream_id = OSCAP.ds_stream_index_get_id(stream_idx)
            checklists = []

            # iterate over checklists and append their ids to the list
            chklist_itr = OSCAP.ds_stream_index_get_checklists(stream_idx)
            while OSCAP.oscap_string_iterator_has_more(chklist_itr):
                checklists.append(OSCAP.oscap_string_iterator_next(chklist_itr))

            # store the list of checklist for the current stream
            self._items[stream_id] = checklists

            OSCAP.oscap_string_iterator_free(chklist_itr)

        OSCAP.ds_stream_index_iterator_free(streams_itr)

    def __del__(self):
        """Destructor for the DataStreamHandler class."""

        # we should free the session
        OSCAP.xccdf_session_free(self._session)

    def get_data_streams(self):
        """
        Method to get a list of data streams found in the data stream collection.

        :return: list of data stream IDs
        :rtype: list of strings

        """

        return self._items.keys()

    def get_data_streams_checklists(self):
        """
        Method to get data streams and their checklists found in the data stream
        collection.

        :return: list of pairs consisting of the IDs of the data streams and
                 lists of their checklists' IDs
        :rtype: list of pairs with a string and list of strings

        """

        return self._items.items()

    def get_checklists(self, data_stream_id):
        """
        Method to get a list of checklists found in the data stream given by the
        data_stream_id.

        :param data_stream_id: ID of the data stream to get checklists from
        :type data_stream_id: str
        :return: list of checklist IDs found in the data stream given by the ID
        :rtype: list of strings

        """

        if not data_stream_id in self._items:
            msg = "Invalid data stream id given: '%s'" % data_stream_id
            raise DataStreamHandlingError(msg)

        return self._items[data_stream_id]

    def get_profiles(self, data_stream_id, checklist_id):
        """
        Method to get a list of profiles defined in the checklist given by the
        checklist_id that is defined in the data stream given by the
        data_stream_id.

        :param data_stream_id: ID of the data stream to get checklists from
        :type data_stream_id: str
        :param checklist_id: ID of the checklist to get profiles from
        :type checklist_id: str
        :return: list of profiles found in the checklist
        :rtype: list of ProfileInfo instances

        """

        cache_id = "%s;%s" % (data_stream_id, checklist_id)
        if cache_id in self._profiles_cache:
            # found in cache, return the value
            return self._profiles_cache[cache_id]

        # not found in the cache, needs to be gathered

        # set the data stream and component (checklist) for the session
        OSCAP.xccdf_session_set_datastream_id(self._session, data_stream_id)
        OSCAP.xccdf_session_set_component_id(self._session, checklist_id)
        if OSCAP.xccdf_session_load(self._session) != 0:
            raise DataStreamHandlingError(OSCAP.oscap_err_desc())

        # will hold items for the profiles for the speficied DS and checklist
        profiles = []

        # get the benchmark (checklist)
        policy_model = OSCAP.xccdf_session_get_policy_model(self._session)
        benchmark = OSCAP.xccdf_policy_model_get_benchmark(policy_model)

        # iterate over the profiles in the benchmark and store them
        profile_itr = OSCAP.xccdf_benchmark_get_profiles(benchmark)
        while OSCAP.xccdf_profile_iterator_has_more(profile_itr):
            profile = OSCAP.xccdf_profile_iterator_next(profile_itr)

            id_ = OSCAP.xccdf_profile_get_id(profile)
            title = oscap_text_itr_get_text(OSCAP.xccdf_profile_get_title(profile))
            desc = oscap_text_itr_get_text(OSCAP.xccdf_profile_get_description(profile))
            info = ProfileInfo(id_, title, desc)

            profiles.append(info)

        OSCAP.xccdf_profile_iterator_free(profile_itr)

        # cache the result
        self._profiles_cache[cache_id] = profiles

        return profiles
