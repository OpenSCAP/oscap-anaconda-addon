import threading
import logging
import pathlib
import shutil
from glob import glob

from pyanaconda.core import constants
from pyanaconda.threading import threadMgr
from pykickstart.errors import KickstartValueError

from org_fedora_oscap import data_fetch, utils
from org_fedora_oscap import common
from org_fedora_oscap import content_handling

from org_fedora_oscap.common import _

log = logging.getLogger("anaconda")


def is_network(scheme):
    return any(
        scheme.startswith(net_prefix)
        for net_prefix in data_fetch.NET_URL_PREFIXES)


class ContentBringer:
    CONTENT_DOWNLOAD_LOCATION = pathlib.Path(common.INSTALLATION_CONTENT_DIR)
    DEFAULT_SSG_DATA_STREAM_PATH = f"{common.SSG_DIR}/{common.SSG_CONTENT}"

    def __init__(self, addon_data):
        self.content_uri_scheme = ""
        self.content_uri_path = ""
        self.fetched_content = ""

        self.activity_lock = threading.Lock()
        self.now_fetching_or_processing = False

        self.CONTENT_DOWNLOAD_LOCATION.mkdir(parents=True, exist_ok=True)

        self._addon_data = addon_data

    def get_content_type(self, url):
        if url.endswith(".rpm"):
            return "rpm"
        elif any(url.endswith(arch_type) for arch_type in common.SUPPORTED_ARCHIVES):
            return "archive"
        else:
            return "file"

    @property
    def content_uri(self):
        return self.content_uri_scheme + "://" + self.content_uri_path

    @content_uri.setter
    def content_uri(self, uri):
        scheme, path = uri.split("://", 1)
        self.content_uri_path = path
        self.content_uri_scheme = scheme

    def fetch_content(self, what_if_fail, ca_certs_path=""):
        """
        Initiate fetch of the content into an appropriate directory

        Args:
            what_if_fail: Callback accepting exception as an argument that
                should handle them in the calling layer.
            ca_certs_path: Path to the HTTPS certificate file
        """
        self.content_uri = self._addon_data.content_url
        shutil.rmtree(self.CONTENT_DOWNLOAD_LOCATION, ignore_errors=True)
        self.CONTENT_DOWNLOAD_LOCATION.mkdir(parents=True, exist_ok=True)
        fetching_thread_name = self._fetch_files(
            self.content_uri_scheme, self.content_uri_path,
            self.CONTENT_DOWNLOAD_LOCATION, ca_certs_path, what_if_fail)
        return fetching_thread_name

    def _fetch_files(self, scheme, path, destdir, ca_certs_path, what_if_fail):
        with self.activity_lock:
            if self.now_fetching_or_processing:
                msg = "Strange, it seems that we are already fetching something."
                log.warn(msg)
                return
            self.now_fetching_or_processing = True

        fetching_thread_name = None
        try:
            fetching_thread_name = self._start_actual_fetch(scheme, path, destdir, ca_certs_path)
        except Exception as exc:
            with self.activity_lock:
                self.now_fetching_or_processing = False
            what_if_fail(exc)

        # We are not finished yet with the fetch
        return fetching_thread_name

    def _start_actual_fetch(self, scheme, path, destdir, ca_certs_path):
        fetching_thread_name = None
        url = scheme + "://" + path

        if "/" not in path:
            msg = f"Missing the path component of the '{url}' URL"
            raise KickstartValueError(msg)
        basename = path.rsplit("/", 1)[1]
        if not basename:
            msg = f"Unable to deduce basename from the '{url}' URL"
            raise KickstartValueError(msg)

        dest = destdir / basename

        if is_network(scheme):
            fetching_thread_name = data_fetch.wait_and_fetch_net_data(
                url,
                dest,
                ca_certs_path
            )
        else:  # invalid schemes are handled down the road
            fetching_thread_name = data_fetch.fetch_local_data(
                url,
                dest,
            )
        return fetching_thread_name

    def finish_content_fetch(self, fetching_thread_name, fingerprint, report_callback, dest_filename,
                             what_if_fail):
        """
        Finish any ongoing fetch and analyze what has been fetched.

        After the fetch is completed, it analyzes verifies fetched content if applicable,
        analyzes it and compiles into an instance of ObtainedContent.

        Args:
            fetching_thread_name: Name of the fetching thread
                or None if we are only after the analysis
            fingerprint: A checksum for downloaded file verification
            report_callback: Means for the method to send user-relevant messages outside
            dest_filename: The target of the fetch operation. Can be falsy -
                in this case there is no content filename defined
            what_if_fail: Callback accepting exception as an argument
                that should handle them in the calling layer.

        Returns:
            Instance of ObtainedContent if everything went well, or None.
        """
        try:
            content = self._finish_actual_fetch(fetching_thread_name, fingerprint, report_callback, dest_filename)
        except Exception as exc:
            what_if_fail(exc)
            content = None
        finally:
            with self.activity_lock:
                self.now_fetching_or_processing = False

        return content

    def _verify_fingerprint(self, dest_filename, fingerprint=""):
        if not fingerprint:
            return

        hash_obj = utils.get_hashing_algorithm(fingerprint)
        digest = utils.get_file_fingerprint(dest_filename,
                                            hash_obj)
        if digest != fingerprint:
            log.error(
                f"File {dest_filename} failed integrity check - assumed a "
                f"{hash_obj.name} hash and '{fingerprint}', got '{digest}'"
            )
            msg = _(f"Integrity check of the content failed - {hash_obj.name} hash didn't match")
            raise content_handling.ContentCheckError(msg)

    def _finish_actual_fetch(self, wait_for, fingerprint, report_callback, dest_filename):
        threadMgr.wait(wait_for)
        actually_fetched_content = wait_for is not None

        if fingerprint and dest_filename:
            self._verify_fingerprint(dest_filename, fingerprint)

        fpaths = self._gather_available_files(actually_fetched_content, dest_filename)

        structured_content = ObtainedContent(self.CONTENT_DOWNLOAD_LOCATION)
        content_type = self.get_content_type(str(dest_filename))
        if content_type in ("archive", "rpm"):
            structured_content.add_content_archive(dest_filename)

        labelled_files = content_handling.identify_files(fpaths)
        for fname, label in labelled_files.items():
            structured_content.add_file(fname, label)

        if fingerprint and dest_filename:
            structured_content.record_verification(dest_filename)

        return structured_content

    def _gather_available_files(self, actually_fetched_content, dest_filename):
        fpaths = []
        if not actually_fetched_content:
            if not dest_filename:  # using scap-security-guide
                fpaths = [self.DEFAULT_SSG_DATA_STREAM_PATH]
            else:  # Using downloaded XCCDF/OVAL/DS/tailoring
                fpaths = pathlib.Path(self.CONTENT_DOWNLOAD_LOCATION).rglob("*")
                fpaths = [str(p) for p in fpaths if p.is_file()]
        else:
            dest_filename = pathlib.Path(dest_filename)
            # RPM is an archive at this phase
            content_type = self.get_content_type(str(dest_filename))
            if content_type in ("archive", "rpm"):
                try:
                    fpaths = common.extract_data(
                        str(dest_filename),
                        str(dest_filename.parent)
                    )
                except common.ExtractionError as err:
                    msg = f"Failed to extract the '{dest_filename}' archive: {str(err)}"
                    log.error(msg)
                    raise err

            elif content_type == "file":
                fpaths = [str(dest_filename)]
            else:
                raise common.OSCAPaddonError("Unsupported content type")
        return fpaths

    def use_downloaded_content(self, content):
        preferred_content = self.get_preferred_content(content)

        # We know that we have ended up with a datastream-like content,
        # but if we can't convert an archive to a datastream.
        # self._addon_data.content_type = "datastream"
        self._addon_data.content_path = str(preferred_content.relative_to(content.root))

        preferred_tailoring = self.get_preferred_tailoring(content)
        if content.tailoring:
            self._addon_data.tailoring_path = str(preferred_tailoring.relative_to(content.root))

    def use_system_content(self, content=None):
        self._addon_data.clear_all()
        self._addon_data.content_type = "scap-security-guide"
        self._addon_data.content_path = common.get_ssg_path()

    def get_preferred_content(self, content):
        if self._addon_data.content_path:
            preferred_content = content.find_expected_usable_content(self._addon_data.content_path)
        else:
            preferred_content = content.select_main_usable_content()
        return preferred_content

    def get_preferred_tailoring(self, content):
        tailoring_path = self._addon_data.tailoring_path
        if tailoring_path:
            if tailoring_path != str(content.tailoring.relative_to(content.root)):
                msg = f"Expected a tailoring {tailoring_path}, but it couldn't be found"
                raise content_handling.ContentHandlingError(msg)
        return content.tailoring


class ObtainedContent:
    """
    This class aims to assist the gathered files discovery -
    the addon can downloaded files directly, or they can be extracted for an archive.
    The class enables user to quickly understand what is available,
    and whether the current set of contents is usable for further processing.
    """
    def __init__(self, root):
        self.labelled_files = dict()
        self.datastream = ""
        self.xccdf = ""
        self.ovals = []
        self.tailoring = ""
        self.archive = ""
        self.verified = ""
        self.root = pathlib.Path(root)

    def record_verification(self, path):
        """
        Declare a file as verified (typically by means of a checksum)
        """
        path = pathlib.Path(path)
        assert path in self.labelled_files
        self.verified = path

    def add_content_archive(self, fname):
        """
        If files come from an archive, record this information using this function.
        """
        path = pathlib.Path(fname)
        self.labelled_files[path] = None
        self.archive = path

    def _assign_content_type(self, attribute_name, new_value):
        old_value = getattr(self, attribute_name)
        if old_value:
            msg = (
                f"When dealing with {attribute_name}, "
                f"there was already the {old_value.name} when setting the new {new_value.name}")
            raise content_handling.ContentHandlingError(msg)
        setattr(self, attribute_name, new_value)

    def add_file(self, fname, label):
        path = pathlib.Path(fname)
        if label == content_handling.CONTENT_TYPES["TAILORING"]:
            self._assign_content_type("tailoring", path)
        elif label == content_handling.CONTENT_TYPES["DATASTREAM"]:
            self._assign_content_type("datastream", path)
        elif label == content_handling.CONTENT_TYPES["OVAL"]:
            self.ovals.append(path)
        elif label == content_handling.CONTENT_TYPES["XCCDF_CHECKLIST"]:
            self._assign_content_type("xccdf", path)
        self.labelled_files[path] = label

    def _datastream_content(self):
        if not self.datastream:
            return None
        if not self.datastream.exists():
            return None
        return self.datastream

    def _xccdf_content(self):
        if not self.xccdf or not self.ovals:
            return None
        some_ovals_exist = any([path.exists() for path in self.ovals])
        if not (self.xccdf.exists() and some_ovals_exist):
            return None
        return self.xccdf

    def find_expected_usable_content(self, relative_expected_content_path):
        content_path = self.root / relative_expected_content_path
        eligible_main_content = (self._datastream_content(), self._xccdf_content())

        if content_path in eligible_main_content:
            return content_path
        else:
            if not content_path.exists():
                msg = f"Couldn't find '{content_path}' among the available content"
            else:
                msg = (
                    f"File '{content_path}' is not a valid datastream "
                    "or a valid XCCDF of a XCCDF-OVAL file tuple")
            raise content_handling.ContentHandlingError(msg)

    def select_main_usable_content(self):
        if self._datastream_content():
            return self._datastream_content()
        elif self._xccdf_content():
            return self._xccdf_content()
        else:
            msg = (
                "Couldn't find a valid datastream or a valid XCCDF-OVAL file tuple "
                "among the available content")
            raise content_handling.ContentHandlingError(msg)
