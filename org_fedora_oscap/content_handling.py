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
Module with various classes for SCAP content processing and retrieving data
from it.

"""

import os.path

from collections import namedtuple
import multiprocessing

from pyanaconda.core.util import execReadlines
try:
    from html.parser import HTMLParser
except ImportError:
    from HTMLParser import HTMLParser

import logging
log = logging.getLogger("anaconda")


CONTENT_TYPES = dict(
    DATASTREAM="Source Data Stream",
    XCCDF_CHECKLIST="XCCDF Checklist",
    OVAL="OVAL Definitions",
    CPE_DICT="CPE Dictionary",
    TAILORING="XCCDF Tailoring",
)


class ContentHandlingError(Exception):
    """Exception class for errors related to SCAP content handling."""

    pass


class ContentCheckError(ContentHandlingError):
    """
    Exception class for errors related to content (integrity,...) checking.
    """

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


# namedtuple class for info about content files found
# pylint: disable-msg=C0103
ContentFiles = namedtuple("ContentFiles", ["xccdf", "cpe", "tailoring"])


def identify_files(fpaths):
    result = {path: get_doc_type(path) for path in fpaths}
    return result


def get_doc_type(file_path):
    content_type = "unknown"
    try:
        for line in execReadlines("oscap", ["info", file_path]):
            if line.startswith("Document type:"):
                _prefix, _sep, type_info = line.partition(":")
                content_type = type_info.strip()
                break
    except OSError:
        # 'oscap info' exitted with a non-zero exit code -> unknown doc
        # type
        pass
    except UnicodeDecodeError:
        # 'oscap info' supplied weird output, which happens when it tries
        # to explain why it can't examine e.g. a JPG.
        pass
    except Exception as e:
        log.warning(f"OSCAP addon: Unexpected error when looking at {file_path}: {str(e)}")
    log.info("OSCAP addon: Identified {file_path} as {content_type}"
             .format(file_path=file_path, content_type=content_type))
    return content_type


def explore_content_files(fpaths):
    """
    Function for finding content files in a list of file paths. SIMPLY PICKS
    THE FIRST USABLE CONTENT FILE OF A PARTICULAR TYPE AND JUST PREFERS DATA
    STREAMS OVER STANDALONE BENCHMARKS.

    :param fpaths: a list of file paths to search for content files in
    :type fpaths: [str]
    :return: ContentFiles instance containing the file names of the XCCDF file,
        CPE dictionary and tailoring file or "" in place of those items
        if not found
    :rtype: ContentFiles

    """
    xccdf_file = ""
    cpe_file = ""
    tailoring_file = ""
    found_ds = False

    for fpath in fpaths:
        doc_type = get_doc_type(fpath)
        if not doc_type:
            continue

        # prefer DS over standalone XCCDF
        if doc_type == "Source Data Stream" and (not xccdf_file or not found_ds):
            xccdf_file = fpath
            found_ds = True
        elif doc_type == "XCCDF Checklist" and not xccdf_file:
            xccdf_file = fpath
        elif doc_type == "CPE Dictionary" and not cpe_file:
            cpe_file = fpath
        elif doc_type == "XCCDF Tailoring" and not tailoring_file:
            tailoring_file = fpath

    # TODO: raise exception if no xccdf_file is found?
    files = ContentFiles(xccdf_file, cpe_file, tailoring_file)
    return files
