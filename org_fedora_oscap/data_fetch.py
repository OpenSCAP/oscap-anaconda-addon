"""
Module for fetching files via HTTP. Directly or over SSL (HTTPS) with server
certificate validation.

"""

import socket
import ssl
import re

# TODO: needs improvements
URL_RE_STR = r"(https?)://([^/]+)(/.*)"
URL_RE = re.compile(URL_RE_STR)

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

class FetchError(DataFetchError):
    """
    Class for the errors when fetching data. Usually due to I/O errors.

    """

    pass

def _throw_away_headers(data):
    """
    Function that throws away HTTP headers from given data.

    :param data: data (usually HTTP response)
    :param data: str
    :return: a tuple containing two items -- a bool value indicating if the end
             of the headers has been found and a string containing the rest of
             the data after removing headers
    :rtype: tuple(bool, str)

    """

    match = re.search("\r\n\r\n", data)
    if not match:
        # not found, still getting headers
        # TODO: check we are really getting headers
        return (False, "")

    if match.end() < len(data):
        # something more than just headers
        return (True, data[match.end():])
    else:
        # just headers
        return (True, "")

def fetch_data(url, out_file, ca_certs=None):
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

    match = URL_RE.match(url)
    if not match:
        msg = "Wrong url not matching '%s'" % URL_RE_STR
        raise WrongRequestError(msg)

    protocol, server, path = match.groups()

    if not out_file:
        raise WrongRequestError("out_file cannot be an empty string")

    if ca_certs and protocol != "https":
        msg = "Cannot verify server certificate when using simple HTTP"
        raise WrongRequestError(msg)

    port_num = 80
    if protocol == "https":
        port_num = 443

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if ca_certs:
        sock = ssl.wrap_socket(sock, ca_certs=ca_certs,
                               cert_reqs=ssl.CERT_REQUIRED)
    try:
        sock.connect((server, port_num))
    except ssl.SSLError as sslerr:
        msg = "Failed to connect to server and validate its certificate: %s"\
                        % sslerr
        raise CertificateValidationError(msg)

    sock.write("GET %s HTTP/1.0\r\n"
                   "Host: %s\r\n\r\n" % (path, server))

    try:
        # read begining of the data
        data = sock.read(READ_BYTES)

        # throw away headers
        (done, rest) = _throw_away_headers(data)
        while not done:
            data = sock.read(READ_BYTES)
            (done, rest) = _throw_away_headers(data)

        # either we have something more or we need to fetch more data
        data = rest or sock.read(READ_BYTES) # I like you, Perl! I mean, Python!
        with open(out_file, "w") as fobj:
            while data:
                fobj.write(data)
                data = sock.read(READ_BYTES)
    except IOError as ioerr:
        msg = "Failed to fetch data: %s" % ioerr
        raise FetchError(msg)

