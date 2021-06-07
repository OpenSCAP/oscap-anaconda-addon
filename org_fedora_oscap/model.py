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

log = logging.getLogger("anaconda")


def is_network(scheme):
    return any(
        scheme.startswith(net_prefix)
        for net_prefix in data_fetch.NET_URL_PREFIXES)


class Model:
    CONTENT_DOWNLOAD_LOCATION = pathlib.Path(common.INSTALLATION_CONTENT_DIR) / "content-download"

    def __init__(self, policy_data):
        self.content_uri_scheme = ""
        self.content_uri_path = ""
        self.fetched_content = ""

        self.activity_lock = threading.Lock()
        self.now_fetching_or_processing = False

        self.CONTENT_DOWNLOAD_LOCATION.mkdir(parents=True, exist_ok=True)

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

    def fetch_content(self, cert, what_if_fail):
        shutil.rmtree(self.CONTENT_DOWNLOAD_LOCATION, ignore_errors=True)
        self.CONTENT_DOWNLOAD_LOCATION.mkdir(parents=True, exist_ok=True)
        return self.fetch_files(self.content_uri_scheme, self.content_uri_path, self.CONTENT_DOWNLOAD_LOCATION, cert, what_if_fail)

    def fetch_files(self, scheme, path, destdir, cert, what_if_fail):
        with self.activity_lock:
            if self.now_fetching_or_processing:
                msg = "Strange, it seems that we are already fetching something."
                log.warn(msg)
                return
            self.now_fetching_or_processing = True

        thread_name = None
        try:
            thread_name = self._start_actual_fetch(scheme, path, destdir, cert)
        except Exception as exc:
            with self.activity_lock:
                self.now_fetching_or_processing = False
            what_if_fail(exc)

        # We are not finished yet with the fetch
        return thread_name

    def _start_actual_fetch(self, scheme, path, destdir, cert):
        thread_name = None
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
            thread_name = data_fetch.wait_and_fetch_net_data(
                url,
                dest,
                cert
            )
        else:  # invalid schemes are handled down the road
            thread_name = data_fetch.fetch_local_data(
                url,
                dest,
            )
        return thread_name

    def finish_content_fetch(self, thread_name, fingerprint, report_callback, dest_filename, after_fetch, what_if_fail):
        """
        Args:
            what_if_fail: Callback accepting exception.
            after_fetch: Callback accepting the content class.
        """
        try:
            content = self._finish_actual_fetch(thread_name, fingerprint, report_callback, dest_filename)
        except Exception as exc:
            what_if_fail(exc)
            content = None
        finally:
            with self.activity_lock:
                self.now_fetching_or_processing = False

        after_fetch(content)

        return content

    def _verify_fingerprint(self, dest_filename, fingerprint=""):
        if not fingerprint:
            return

        hash_obj = utils.get_hashing_algorithm(fingerprint)
        digest = utils.get_file_fingerprint(dest_filename,
                                            hash_obj)
        if digest != fingerprint:
            log.error(
                "File {dest_filename} failed integrity check - assumed a "
                "{hash_obj.name} hash and '{fingerprint}', got '{digest}'"
            )
            msg = f"Integrity check of the content failed - {hash_obj.name} hash didn't match"
            raise content_handling.ContentCheckError(msg)

    def _finish_actual_fetch(self, wait_for, fingerprint, report_callback, dest_filename):
        threadMgr.wait(wait_for)
        actually_fetched_content = wait_for is not None

        self._verify_fingerprint(dest_filename, fingerprint)

        content = ObtainedContent(self.CONTENT_DOWNLOAD_LOCATION)

        report_callback("Analyzing content.")
        if not actually_fetched_content:
            if not dest_filename:  # using scap-security-guide
                fpaths = [f"{common.SSG_DIR}/{common.SSG_CONTENT}"]
                labelled_files = content_handling.identify_files(fpaths)
            else:  # Using downloaded XCCDF/OVAL/DS/tailoring
                fpaths = glob(str(self.CONTENT_DOWNLOAD_LOCATION / "*.xml"))
                labelled_files = content_handling.identify_files(fpaths)
        else:
            dest_filename = pathlib.Path(dest_filename)
            # RPM is an archive at this phase
            content_type = self.get_content_type(str(dest_filename))
            if content_type in ("archive", "rpm"):
                # extract the content
                content.add_content_archive(dest_filename)
                try:
                    fpaths = common.extract_data(
                        str(dest_filename),
                        str(dest_filename.parent)
                    )
                except common.ExtractionError as err:
                    msg = f"Failed to extract the '{dest_filename}' archive: {str(err)}"
                    log.error(msg)
                    raise err

                # and populate missing fields
                labelled_files = content_handling.identify_files(fpaths)

            elif content_type == "file":
                labelled_files = content_handling.identify_files([str(dest_filename)])
            else:
                raise common.OSCAPaddonError("Unsupported content type")

        for f, l in labelled_files.items():
            content.add_file(f, l)

        if fingerprint:
            content.record_verification(dest_filename)

        return content


class ObtainedContent:
    def __init__(self, root):
        self.labelled_files = dict()
        self.datastream = ""
        self.xccdf = ""
        self.oval = ""
        self.tailoring = ""
        self.archive = ""
        self.verified = ""
        self.root = pathlib.Path(root)

    def record_verification(self, path):
        assert path in self.labelled_files
        self.verified = path

    def add_content_archive(self, fname):
        path = pathlib.Path(fname)
        self.labelled_files[path] = None
        self.archive = path

    def _assign_content_type(self, attribute_name, new_value):
        old_value = getattr(self, attribute_name)
        if old_value:
            msg = (
                f"When dealing with {attribute_name}, "
                f"there was already the {old_value.name} when setting the new {new_value.name}")
            raise RuntimeError(msg)
        setattr(self, attribute_name, new_value)

    def add_file(self, fname, label):
        path = pathlib.Path(fname)
        if label == content_handling.CONTENT_TYPES["TAILORING"]:
            self._assign_content_type("tailoring", path)
        elif label == content_handling.CONTENT_TYPES["DATASTREAM"]:
            self._assign_content_type("datastream", path)
        elif label == content_handling.CONTENT_TYPES["OVAL"]:
            self._assign_content_type("oval", path)
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
        if not self.xccdf or not self.oval:
            return None
        if not (self.xccdf.exists() and self.oval.exists()):
            return None
        return self.xccdf

    def find_expected_usable_content(self, relative_expected_content_path):
        content_path = self.root / relative_expected_content_path
        elligible_main_content = (self._datastream_content(), self._xccdf_content())

        if content_path in elligible_main_content:
            return content_path
        else:
            if not content_path.exists():
                msg = f"Couldn't find '{content_path}' among the available content"
            else:
                msg = (
                    "File '{content_path}' is not a valid datastream "
                    "or a valid XCCDF of a XCCDF-OVAL file tuple")
            raise content_handling.ContentHandlingError(msg)

    def select_main_usable_content(self):
        elligible_main_content = (self._datastream_content(), self._xccdf_content())
        if not any(elligible_main_content):
            msg = (
                "Couldn't find a valid datastream or a valid XCCDF-OVAL file tuple "
                "among the available content")
            raise content_handling.ContentHandlingError(msg)
        if elligible_main_content[0]:
            return elligible_main_content[0]
        else:
            return elligible_main_content[1]
