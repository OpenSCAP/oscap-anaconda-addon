"""
Module for fetching files via HTTP and FTP. Directly or over SSL (HTTPS) with
server certificate validation.

"""

import re
import os
import os.path
import pycurl

from pyanaconda.core.configuration.anaconda import conf
from pyanaconda.core import constants
from pyanaconda.threading import threadMgr, AnacondaThread
from pyanaconda.modules.common.constants.services import NETWORK

from org_fedora_oscap import common
from org_fedora_oscap.common import _
from org_fedora_oscap import utils

import logging
log = logging.getLogger("anaconda")


# everything else should be private
__all__ = ["fetch_data", "can_fetch_from"]

# prefixes of the URLs that need network connection
NET_URL_PREFIXES = ("http", "https", "ftp")

# prefixes of the URLs that may not need network connection
LOCAL_URL_PREFIXES = ("file",)

# TODO: needs improvements
HTTP_URL_RE_STR = r"(https?)://(.*)"
HTTP_URL_RE = re.compile(HTTP_URL_RE_STR)

FTP_URL_RE_STR = r"(ftp)://(.*)"
FTP_URL_RE = re.compile(FTP_URL_RE_STR)

FILE_URL_RE_STR = r"(file)://(.*)"
FILE_URL_RE = re.compile(FILE_URL_RE_STR)


class DataFetchError(common.OSCAPaddonError):
    """Parent class for the exception classes defined in this module."""

    pass


class CertificateValidationError(DataFetchError):
    """Class for the certificate validation related errors."""

    pass


class WrongRequestError(DataFetchError):
    """Class for the wrong combination of parameters errors."""

    pass


class UnknownURLformatError(DataFetchError):
    """Class for invalid URL cases."""

    pass


class FetchError(DataFetchError):
    """
    Class for the errors when fetching data. Usually due to I/O errors.

    """

    pass


def fetch_local_data(url, out_file):
    """
    Function that fetches data locally.

    :see: org_fedora_oscap.data_fetch.fetch_data
    :return: the name of the thread running fetch_data
    :rtype: str

    """
    fetch_data_thread = AnacondaThread(name=common.THREAD_FETCH_DATA,
                                       target=fetch_data,
                                       args=(url, out_file, None),
                                       fatal=False)

    # register and run the thread
    threadMgr.add(fetch_data_thread)

    return common.THREAD_FETCH_DATA


def wait_and_fetch_net_data(url, out_file, ca_certs_path=None):
    """
    Function that waits for network connection and starts a thread that fetches
    data over network.

    :see: org_fedora_oscap.data_fetch.fetch_data
    :return: the name of the thread running fetch_data
    :rtype: str

    """

    # get thread that tries to establish a network connection
    nm_conn_thread = threadMgr.get(constants.THREAD_WAIT_FOR_CONNECTING_NM)
    if nm_conn_thread:
        # NM still connecting, wait for it to finish
        nm_conn_thread.join()

    network_proxy = NETWORK.get_proxy()
    if not network_proxy.Connected:
        raise common.OSCAPaddonNetworkError(_("Network connection needed to fetch data."))

    log.info(f"Fetching data from {url}")
    fetch_data_thread = AnacondaThread(name=common.THREAD_FETCH_DATA,
                                       target=fetch_data,
                                       args=(url, out_file, ca_certs_path),
                                       fatal=False)

    # register and run the thread
    threadMgr.add(fetch_data_thread)

    return common.THREAD_FETCH_DATA


def can_fetch_from(url):
    """
    Function telling whether the fetch_data function understands the type of
    given URL or not.

    :param url: URL
    :type url: str
    :return: whether the type of the URL is supported or not
    :rtype: str

    """
    resources = NET_URL_PREFIXES + LOCAL_URL_PREFIXES
    return any(url.startswith(prefix) for prefix in resources)


def fetch_data(url, out_file, ca_certs_path=None):
    """
    Fetch data from a given URL. If the URL starts with https://, ca_certs_path can
    be a path to PEM file with CA certificate chain to validate server
    certificate.

    :param url: URL of the data
    :type url: str
    :param out_file: path to the output file
    :type out_file: str
    :param ca_certs_path: path to a PEM file with CA certificate chain
    :type ca_certs_path: str
    :raise WrongRequestError: if a wrong combination of arguments is passed
                              (ca_certs_path file path given and url starting with
                              http://) or arguments don't have required format
    :raise CertificateValidationError: if server certificate validation fails
    :raise FetchError: if data fetching fails (usually due to I/O errors)

    """

    # create the directory for the out_file if it doesn't exist
    out_dir = os.path.dirname(out_file)
    utils.ensure_dir_exists(out_dir)

    if can_fetch_from(url):
        _curl_fetch(url, out_file, ca_certs_path)
    else:
        msg = "Cannot fetch data from '%s': unknown URL format" % url
        raise UnknownURLformatError(msg)
    log.info(f"Data fetch from {url} completed")


def _curl_fetch(url, out_file, ca_certs_path=None):
    """
    Function that fetches data and writes it out to the given file path. If a
    path to the file with CA certificates is given and the url starts with
    'https', the server certificate is validated.

    :param url: url of the data that has to start with 'http://' or "https://"
    :type url: str
    :param out_file: path to the output file
    :type out_file: str
    :param ca_certs_path: path to the file with CA certificates for server
                     certificate validation
    :type ca_certs_path: str
    :raise WrongRequestError: if a wrong combination of arguments is passed
                              (ca_certs_path file path given and url starting with
                              http://) or arguments don't have required format
    :raise CertificateValidationError: if server certificate validation fails
    :raise FetchError: if data fetching fails (usually due to I/O errors)

    """

    if url.startswith("ftp"):
        match = FTP_URL_RE.match(url)
        if not match:
            msg = "Wrong url not matching '%s'" % FTP_URL_RE_STR
            raise WrongRequestError(msg)
        else:
            protocol, path = match.groups()
            if '@' not in path:
                # no user:pass given -> use anonymous login to the FTP server
                url = protocol + "://anonymous:@" + path
    elif url.startswith("file"):
        match = FILE_URL_RE.match(url)
        if not match:
            msg = "Wrong url not matching '%s'" % FILE_URL_RE_STR
            raise WrongRequestError(msg)
    else:
        match = HTTP_URL_RE.match(url)
        if not match:
            msg = "Wrong url not matching '%s'" % HTTP_URL_RE_STR
            raise WrongRequestError(msg)

    # the first group contains the protocol, the second one the rest
    protocol = match.groups()[0]

    if not out_file:
        raise WrongRequestError("out_file cannot be an empty string")

    if ca_certs_path and protocol != "https":
        msg = "Cannot verify server certificate when using plain HTTP"
        raise WrongRequestError(msg)

    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, url)

    if ca_certs_path and protocol == "https":
        # the strictest verification
        curl.setopt(pycurl.SSL_VERIFYHOST, 2)
        curl.setopt(pycurl.SSL_VERIFYPEER, 1)
        curl.setopt(pycurl.CAINFO, ca_certs_path)

    # may be turned off by flags (specified on command line, take precedence)
    if not conf.payload.verify_ssl:
        log.warning("Disabling SSL verification due to the noverifyssl flag")
        curl.setopt(pycurl.SSL_VERIFYHOST, 0)
        curl.setopt(pycurl.SSL_VERIFYPEER, 0)

    try:
        with open(out_file, "wb") as fobj:
            curl.setopt(pycurl.WRITEDATA, fobj)
            curl.perform()
    except pycurl.error as err:
        # first arg is the error code
        if err.args[0] == pycurl.E_SSL_CACERT:
            msg = "Failed to connect to server and validate its "\
                  "certificate: %s" % err
            raise CertificateValidationError(msg)
        else:
            msg = "Failed to fetch data: %s" % err
            raise FetchError(msg)

    if protocol in ("http", "https"):
        return_code = curl.getinfo(pycurl.HTTP_CODE)
        if 400 <= return_code < 600:
            msg = _(f"Failed to fetch data - the request returned HTTP error code {return_code}")
            raise FetchError(msg)
