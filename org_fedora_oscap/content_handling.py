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

import os.path

from collections import namedtuple, OrderedDict
from openscap_api import OSCAP
from pyanaconda.iutil import execReadlines
try:
    from html.parser import HTMLParser
except ImportError:
    from HTMLParser import HTMLParser


class ContentHandlingError(Exception):
    """Exception class for errors related to SCAP content handling."""

    pass


class DataStreamHandlingError(ContentHandlingError):
    """Exception class for errors related to data stream handling."""

    pass


class BenchmarkHandlingError(ContentHandlingError):
    """Exception class for errors related to benchmark handling."""

    pass


class ContentCheckError(ContentHandlingError):
    """Exception class for errors related to content (integrity,...) checking."""

    pass


class ParseHTMLContent(HTMLParser):
    """Parser class for HTML tags within content"""

    def __init__(self):
        HTMLParser.__init__(self)
        self.content = ""

    def handle_starttag(self, tag, attrs):
        if tag == "html:ul":
            self.content += "\n"
        elif tag == "html:li":
            self.content += "\n"
        elif tag == "html:br":
            self.content += "\n"

    def handle_endtag(self, tag):
        if tag == "html:ul":
            self.content += "\n"
        elif tag == "html:li":
            self.content += "\n"

    def handle_data(self, data):
        self.content += data.strip()

    def get_content(self):
        return self.content


def parse_HTML_from_content(content):
    """This is a very simple HTML to text parser.

    HTML tags will be removed while trying to maintain readability
    of content.

    :param content: content whose HTML tags will be parsed
    :return: content without HTML tags
    """

    parser = ParseHTMLContent()
    parser.feed(content)
    return parser.get_content()


# namedtuple class (not a constant, pylint!) for info about a XCCDF profile
# pylint: disable-msg=C0103
ProfileInfo = namedtuple("ProfileInfo", ["id", "title", "description"])

# namedtuple class for info about content files found
# pylint: disable-msg=C0103
ContentFiles = namedtuple("ContentFiles", ["xccdf", "cpe", "tailoring"])


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


def explore_content_files(fpaths):
    """
    Function for finding content files in a list of file paths. SIMPLY PICKS
    THE FIRST USABLE CONTENT FILE OF A PARTICULAR TYPE AND JUST PREFERS DATA
    STREAMS OVER STANDALONE BENCHMARKS.

    :param fpaths: a list of file paths to search for content files in
    :type fpaths: [str]
    :return: a tuple containing the content handling class and an ContentFiles
             instance containing the file names of the XCCDF file, CPE
             dictionary and tailoring file or "" in place of those items if not
             found
    :rtype: (class, ContentFiles)

    """

    def get_doc_type(file_path):
        try:
            for line in execReadlines("oscap", ["info", file_path]):
                if line.startswith("Document type:"):
                    _prefix, _sep, type_info = line.partition(":")
                    return type_info.strip()
        except OSError:
            # 'oscap info' exitted with a non-zero exit code -> unknown doc type
            return None

    xccdf_file = ""
    cpe_file = ""
    tailoring_file = ""
    found_ds = False
    content_class = None

    for fpath in fpaths:
        doc_type = get_doc_type(fpath)
        if not doc_type:
            continue

        # prefer DS over standalone XCCDF
        if doc_type == "Source Data Stream" and (not xccdf_file or not found_ds):
            xccdf_file = fpath
            content_class = DataStreamHandler
            found_ds = True
        elif doc_type == "XCCDF Checklist" and not xccdf_file:
            xccdf_file = fpath
            content_class = BenchmarkHandler
        elif doc_type == "CPE Dictionary" and not cpe_file:
            cpe_file = fpath
        elif doc_type == "XCCDF Tailoring" and not tailoring_file:
            tailoring_file = fpath

    # TODO: raise exception if no xccdf_file is found?
    files = ContentFiles(xccdf_file, cpe_file, tailoring_file)
    return (content_class, files)


class DataStreamHandler(object):
    """
    Class for handling data streams in the data stream collection and
    retrieving data from it. For example a list of data stream indices,
    checklists in a given data stream of profiles.

    """

    def __init__(self, dsc_file_path, tailoring_file_path=""):
        """
        Constructor for the DataStreamHandler class.

        :param dsc_file_path: path to a file with a data stream collection
        :type dsc_file_path: str
        :param tailoring_file_path: path to a tailoring file
        :type tailoring_file_path: str

        """

        # is used to speed up getting lists of profiles
        self._profiles_cache = dict()

        if not os.path.exists(dsc_file_path):
            msg = "Invalid file path: '%s'" % dsc_file_path
            raise DataStreamHandlingError(msg)

        self._dsc_file_path = dsc_file_path

        # create an XCCDF session for the file
        self._session = OSCAP.xccdf_session_new(dsc_file_path)
        if not self._session:
            msg = "'%s' is not a valid SCAP content file" % dsc_file_path
            raise DataStreamHandlingError(msg)
        if OSCAP.xccdf_session_load(self._session) != 0:
            raise DataStreamHandlingError(OSCAP.oscap_err_desc())

        if tailoring_file_path:
            OSCAP.xccdf_session_set_user_tailoring_file(self._session,
                                                        tailoring_file_path)

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

        if '_session' in locals():
            # we should free the session
            OSCAP.xccdf_session_free(self._session)

    def get_data_streams(self):
        """
        Method to get a list of data streams found in the data stream
        collection.

        :return: list of data stream IDs
        :rtype: list of strings

        """

        return self._items.keys()

    def get_data_streams_checklists(self):
        """
        Method to get data streams and their checklists found in the data
        stream collection.

        :return: a dictionary consisting of the IDs of the data streams as keys
                 and lists of their checklists' IDs as values
        :rtype: dict(str -> list of strings)

        """

        # easy, we already have exactly what should be returned, just create a
        # copy, so that the caller cannot modify our internal attributes
        return dict(self._items)

    def get_checklists(self, data_stream_id):
        """
        Method to get a list of checklists found in the data stream given by
        the data_stream_id.

        :param data_stream_id: ID of the data stream to get checklists from
        :type data_stream_id: str
        :return: list of checklist IDs found in the data stream given by the ID
        :rtype: list of strings

        """

        if data_stream_id not in self._items:
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
        OSCAP.xccdf_session_free(self._session)

        self._session = OSCAP.xccdf_session_new(self._dsc_file_path)
        if not self._session:
            msg = "'%s' is not a valid SCAP content file" % self._dsc_file_path
            raise DataStreamHandlingError(msg)

        OSCAP.xccdf_session_set_datastream_id(self._session, data_stream_id)
        OSCAP.xccdf_session_set_component_id(self._session, checklist_id)
        if OSCAP.xccdf_session_load(self._session) != 0:
            raise DataStreamHandlingError(OSCAP.oscap_err_desc())

        # get the benchmark (checklist)
        policy_model = OSCAP.xccdf_session_get_policy_model(self._session)

        default_policy = OSCAP.xccdf_policy_new(policy_model, None)
        default_rules_count = OSCAP.xccdf_policy_get_selected_rules_count(default_policy)

        # will hold items for the profiles for the speficied DS and checklist
        profiles = []

        if default_rules_count > 0:
            profiles.append(ProfileInfo("default", "Default",
                            "The implicit XCCDF profile. Usually, the default contains no rules."))

        benchmark = OSCAP.xccdf_policy_model_get_benchmark(policy_model)

        # iterate over the profiles in the benchmark and store them
        profile_itr = OSCAP.xccdf_benchmark_get_profiles(benchmark)
        while OSCAP.xccdf_profile_iterator_has_more(profile_itr):
            profile = OSCAP.xccdf_profile_iterator_next(profile_itr)

            id_ = OSCAP.xccdf_profile_get_id(profile)
            title = oscap_text_itr_get_text(OSCAP.xccdf_profile_get_title(profile))
            desc = parse_HTML_from_content(oscap_text_itr_get_text(OSCAP.xccdf_profile_get_description(profile)))
            info = ProfileInfo(id_, title, desc)

            profiles.append(info)

        OSCAP.xccdf_profile_iterator_free(profile_itr)

        # cache the result
        self._profiles_cache[cache_id] = profiles

        return profiles


class BenchmarkHandler(object):
    """
    Class for handling XCCDF benchmark and retrieving data from it (mainly the
    list of profiles).

    """

    def __init__(self, xccdf_file_path, tailoring_file_path=""):
        """
        Constructor for the BenchmarkHandler class.

        :param xccdf_file_path: path to a file with an XCCDF benchmark
        :type xccdf_file_path: str
        :param tailoring_file_path: path to a tailoring file
        :type tailoring_file_path: str
        """

        if not os.path.exists(xccdf_file_path):
            msg = "Invalid file path: '%s'" % xccdf_file_path
            raise BenchmarkHandlingError(msg)

        session = OSCAP.xccdf_session_new(xccdf_file_path)
        if not session:
            msg = "'%s' is not a valid SCAP content file" % xccdf_file_path
            raise BenchmarkHandlingError(msg)

        if tailoring_file_path:
            OSCAP.xccdf_session_set_user_tailoring_file(session,
                                                        tailoring_file_path)
        if OSCAP.xccdf_session_load(session) != 0:
            raise BenchmarkHandlingError(OSCAP.oscap_err_desc())

        # get the benchmark object
        policy_model = OSCAP.xccdf_session_get_policy_model(session)
        benchmark = OSCAP.xccdf_policy_model_get_benchmark(policy_model)

        default_policy = OSCAP.xccdf_policy_new(policy_model, None)
        default_rules_count = OSCAP.xccdf_policy_get_selected_rules_count(default_policy)

        # stores a list of profiles in the benchmark
        self._profiles = []

        if default_rules_count > 0:
            self._profiles.append(ProfileInfo("default", "Default",
                                  "The implicit XCCDF profile. Usually, the default contains no rules."))

        if not benchmark:
            msg = "Not a valid benchmark file: '%s'" % xccdf_file_path
            raise BenchmarkHandlingError(msg)

        # iterate over the profiles in the benchmark and store them
        profile_itr = OSCAP.xccdf_benchmark_get_profiles(benchmark)
        while OSCAP.xccdf_profile_iterator_has_more(profile_itr):
            profile = OSCAP.xccdf_profile_iterator_next(profile_itr)

            id_ = OSCAP.xccdf_profile_get_id(profile)
            title = oscap_text_itr_get_text(OSCAP.xccdf_profile_get_title(profile))
            desc = parse_HTML_from_content(oscap_text_itr_get_text(OSCAP.xccdf_profile_get_description(profile)))
            info = ProfileInfo(id_, title, desc)

            self._profiles.append(info)

        if tailoring_file_path:
            tailoring = OSCAP.xccdf_policy_model_get_tailoring(policy_model)
            profile_itr = OSCAP.xccdf_tailoring_get_profiles(tailoring)
            while OSCAP.xccdf_profile_iterator_has_more(profile_itr):
                profile = OSCAP.xccdf_profile_iterator_next(profile_itr)

                id_ = OSCAP.xccdf_profile_get_id(profile)
                title = oscap_text_itr_get_text(OSCAP.xccdf_profile_get_title(profile))
                desc = parse_HTML_from_content(oscap_text_itr_get_text(OSCAP.xccdf_profile_get_description(profile)))
                info = ProfileInfo(id_, title, desc)

                self._profiles.append(info)

        OSCAP.xccdf_profile_iterator_free(profile_itr)
        OSCAP.xccdf_session_free(session)

    @property
    def profiles(self):
        """Property for the list of profiles defined in the benchmark."""

        return self._profiles
