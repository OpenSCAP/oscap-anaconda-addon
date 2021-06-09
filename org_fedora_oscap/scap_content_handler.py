#
# Copyright (C) 2021 Red Hat, Inc.
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
# Red Hat Author(s): Jan Černý <jcerny@redhat.com>
#

from collections import namedtuple
import os
import re
import xml.etree.ElementTree as ET

from org_fedora_oscap.content_handling import parse_HTML_from_content

# namedtuple class (not a constant, pylint!) for info about a XCCDF profile
# pylint: disable-msg=C0103
ProfileInfo = namedtuple("ProfileInfo", ["id", "title", "description"])

ns = {
    "ds": "http://scap.nist.gov/schema/scap/source/1.2",
    "xccdf-1.1": "http://checklists.nist.gov/xccdf/1.1",
    "xccdf-1.2": "http://checklists.nist.gov/xccdf/1.2",
    "xlink": "http://www.w3.org/1999/xlink"
}


class SCAPContentHandlerError(Exception):
    """Exception class for errors related to SCAP content handling."""
    pass


class SCAPContentHandler:
    def __init__(self, file_path, tailoring_file_path=None):
        """
        Constructor for the SCAPContentHandler class.

        :param file_path: path to an SCAP file (only SCAP source data streams,
        XCCDF files and tailoring files are supported)
        :type file_path: str
        :param tailoring_file_path: path to the tailoring file, can be None if
            no tailoring exists
        :type tailoring_file_path: str
        """
        self.file_path = file_path
        tree = ET.parse(file_path)
        self.root = tree.getroot()
        if not tailoring_file_path:
            self.tailoring = None
        else:
            self.tailoring = ET.parse(tailoring_file_path).getroot()
        self.scap_type = self._get_scap_type(self.root)
        self._data_stream_id = None
        self._checklist_id = None

    def _get_scap_type(self, root):
        if root.tag == f"{{{ns['ds']}}}data-stream-collection":
            return "SCAP_SOURCE_DATA_STREAM"
        elif (root.tag == f"{{{ns['xccdf-1.1']}}}Benchmark" or
                root.tag == f"{{{ns['xccdf-1.2']}}}Benchmark"):
            return "XCCDF"
        elif (root.tag == f"{{{ns['xccdf-1.1']}}}Tailoring" or
                root.tag == f"{{{ns['xccdf-1.2']}}}Tailoring"):
            return "TAILORING"
        else:
            msg = f"Unsupported SCAP content type {root.tag}"
            raise SCAPContentHandlerError(msg)

    def get_data_streams_checklists(self):
        """
        Method to get data streams and their checklists found in the SCAP
        source data stream represented by the SCAPContentHandler.

        :return: a dictionary consisting of the IDs of the data streams as keys
                 and lists of their checklists' IDs as values
                 None if the file isn't a SCAP source data stream
        :rtype: dict(str -> list of strings)
        """
        if self.scap_type != "SCAP_SOURCE_DATA_STREAM":
            return None
        checklists = {}
        for data_stream in self.root.findall("ds:data-stream", ns):
            data_stream_id = data_stream.get("id")
            crefs = []
            for cref in data_stream.findall(
                    "ds:checklists/ds:component-ref", ns):
                cref_id = cref.get("id")
                crefs.append(cref_id)
            checklists[data_stream_id] = crefs
        return checklists

    def _parse_profiles_from_xccdf(self, benchmark):
        if benchmark is None:
            return []

        # Find out the namespace of the benchmark element
        match = re.match(r"^\{([^}]+)\}", benchmark.tag)
        if match is None:
            raise SCAPContentHandlerError("The document has no namespace.")
        root_element_ns = match.groups()[0]
        for prefix, uri in ns.items():
            if uri == root_element_ns:
                xccdf_ns_prefix = prefix
                break
        else:
            raise SCAPContentHandlerError(
                f"Unsupported XML namespace {root_element_ns}")

        profiles = []
        for profile in benchmark.findall(f"{xccdf_ns_prefix}:Profile", ns):
            profile_id = profile.get("id")
            title = profile.find(f"{xccdf_ns_prefix}:title", ns)
            description = profile.find(f"{xccdf_ns_prefix}:description", ns)
            if description is None:
                description_text = ""
            else:
                description_text = parse_HTML_from_content(description.text)
            profile_info = ProfileInfo(
                profile_id, title.text, description_text)
            profiles.append(profile_info)
        # if there are no profiles we would like to prevent empty profile
        # selection list in the GUI so we create the default profile
        if len(profiles) == 0:
            default_profile = ProfileInfo(
                "default",
                "Default",
                "The implicit XCCDF profile. Usually, the default profile "
                "contains no rules.")
            profiles.append(default_profile)
        return profiles

    def select_checklist(self, data_stream_id, checklist_id):
        """
        Method to select a specific XCCDF Benchmark using
        :param data_stream_id: value of ds:data-stream/@id
        :type data_stream_id: str
        :param checklist_id: value of ds:component-ref/@id pointing to
            an xccdf:Benchmark
        :type checklist_id: str
        :return: None

        """
        self._data_stream_id = data_stream_id
        self._checklist_id = checklist_id

    def _find_benchmark_in_source_data_stream(self):
        cref_xpath = f"ds:data-stream[@id='{self._data_stream_id}']/" \
            f"ds:checklists/ds:component-ref[@id='{self._checklist_id}']"
        cref = self.root.find(cref_xpath, ns)
        if cref is None:
            msg = f"Can't find ds:component-ref " \
                f"with id='{self._checklist_id}' " \
                f"in ds:datastream with id='{self._data_stream_id}'"
            raise SCAPContentHandlerError(msg)
        cref_href = cref.get(f"{{{ns['xlink']}}}href")
        if cref_href is None:
            msg = f"The ds:component-ref with id='{self._checklist_id} '" \
                f"in ds:datastream with id='{self._data_stream_id}' " \
                f"doesn't have a xlink:href attribute."
            raise SCAPContentHandlerError(msg)
        if not cref_href.startswith("#"):
            msg = f"The component {cref_href} isn't local."
            raise SCAPContentHandlerError(msg)
        component_id = cref_href[1:]
        component = self.root.find(
            f"ds:component[@id='{component_id}']", ns)
        if component is None:
            msg = f"Can't find component {component_id}"
            raise SCAPContentHandlerError(msg)
        benchmark = component.find("xccdf-1.1:Benchmark", ns)
        if benchmark is None:
            benchmark = component.find("xccdf-1.2:Benchmark", ns)
        if benchmark is None:
            msg = f"The component {cref_href} doesn't contain an XCCDF " \
                "Benchmark."
            raise SCAPContentHandlerError(msg)
        return benchmark

    def get_profiles(self):
        """
        Method to get a list of profiles defined in the currently selected
        checklist that is defined in the currently selected data stream.

        :return: list of profiles found in the checklist
        :rtype: list of ProfileInfo instances

        """
        if self.scap_type not in ("XCCDF", "SCAP_SOURCE_DATA_STREAM"):
            msg = f"Unsupported SCAP content type '{self.scap_type}'."
            raise SCAPContentHandlerError(msg)
        if self.scap_type == "XCCDF" and (
                self._data_stream_id is not None or
                self._checklist_id is not None):
            msg = "For XCCDF documents, the data_stream_id and checklist_id " \
                "must be both None."
            raise SCAPContentHandlerError(msg)
        if self.scap_type == "SCAP_SOURCE_DATA_STREAM" and (
                self._data_stream_id is None or self._checklist_id is None):
            msg = "For SCAP source data streams, data_stream_id and " \
                "checklist_id must be both different than None"
            raise SCAPContentHandlerError(msg)

        if self.scap_type == "SCAP_SOURCE_DATA_STREAM":
            benchmark = self._find_benchmark_in_source_data_stream()
        else:
            benchmark = self.root
        benchmark_profiles = self._parse_profiles_from_xccdf(benchmark)
        tailoring_profiles = self._parse_profiles_from_xccdf(self.tailoring)
        return benchmark_profiles + tailoring_profiles
