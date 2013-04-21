"""
Module for fetching files via HTTP. Directly or over SSL (HTTPS) with server
certificate validation.

"""

import re
import os
import os.path
import pycurl

from org_fedora_oscap import utils

# everything else should be private
__all__ = ["fetch_data"]

# prefixes of the URLs that need network connection
NET_URL_PREFIXES = ("http", "https")

# TODO: needs improvements
HTTP_URL_RE_STR = r"(https?)://(.*)"
HTTP_URL_RE = re.compile(HTTP_URL_RE_STR)

READ_BYTES = 4096

class DataFetchError(Exception):
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

def fetch_data(url, out_file, ca_certs=None):
    """
    Fetch data from a given URL. If the URL starts with https://, ca_certs can
    be a path to PEM file with CA certificate chain to validate server
    certificate.

    :param url: URL of the data
    :type url: str
    :param out_file: path to the output file
    :type out_file: str
    :param ca_certs: path to a PEM file with CA certificate chain
    :type ca_certs: str
    :raise WrongRequestError: if a wrong combination of arguments is passed
                              (ca_certs file path given and url starting with
                              http://) or arguments don't have required format
    :raise CertificateValidationError: if server certificate validation fails
    :raise FetchError: if data fetching fails (usually due to I/O errors)

    """

    # create the directory for the out_file if it doesn't exist
    out_dir = os.path.dirname(out_file)
    utils.ensure_dir_exists(out_dir)

    if url.startswith("http://") or url.startswith("https://"):
        _fetch_http_data(url, out_file, ca_certs)
    else:
        msg = "Cannot fetch data from '%s': unknown URL format" % url
        raise UnknownURLformatError(msg)

def _fetch_http_data(url, out_file, ca_certs=None):
    """
    Function that fetches data and writes it out to the given file path. If a
    path to the file with CA certificates is given and the url starts with
    'https', the server certificate is validated.

    :param url: url of the data that has to start with 'http://' or "https://"
    :type url: str
    :param out_file: path to the output file
    :type out_file: str
    :param ca_certs: path to the file with CA certificates for server
                     certificate validation
    :type ca_certs: str
    :raise WrongRequestError: if a wrong combination of arguments is passed
                              (ca_certs file path given and url starting with
                              http://) or arguments don't have required format
    :raise CertificateValidationError: if server certificate validation fails
    :raise FetchError: if data fetching fails (usually due to I/O errors)

    """

    match = HTTP_URL_RE.match(url)
    if not match:
        msg = "Wrong url not matching '%s'" % HTTP_URL_RE_STR
        raise WrongRequestError(msg)

    # the first group contains the protocol, the second one the rest
    protocol = match.groups()[0]

    if not out_file:
        raise WrongRequestError("out_file cannot be an empty string")

    if ca_certs and protocol != "https":
        msg = "Cannot verify server certificate when using plain HTTP"
        raise WrongRequestError(msg)

    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, url)

    if ca_certs and protocol == "https":
        # the strictest verification
        curl.setopt(pycurl.SSL_VERIFYHOST, 2)
        curl.setopt(pycurl.CAINFO, ca_certs)

    try:
        with open(out_file, "w") as fobj:
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
