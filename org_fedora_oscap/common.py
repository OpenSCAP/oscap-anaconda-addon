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
Module with various classes and functions needed by the OSCAP addon that are
not specific to any installation mode (tui, gui, ks).

"""

import os
import tempfile
import subprocess
import zipfile
import tarfile
import cpioarchive
import re
import logging

from collections import namedtuple
from functools import wraps
from pyanaconda import constants
from pyanaconda import nm
from pyanaconda.threads import threadMgr, AnacondaThread
from org_fedora_oscap import utils
from org_fedora_oscap.data_fetch import fetch_data

log = logging.getLogger("anaconda")

# everything else should be private
__all__ = ["run_oscap_remediate", "get_fix_rules_pre",
           "wait_and_fetch_net_data", "extract_data", "strip_content_dir",
           "OSCAPaddonError"]

INSTALLATION_CONTENT_DIR = "/tmp/openscap_data/"
TARGET_CONTENT_DIR = "/root/openscap_data/"

SSG_DIR = "/usr/share/xml/scap/ssg/content/"
SSG_CONTENT = "ssg-rhel7-ds.xml"
if constants.shortProductName != 'anaconda':
    if constants.shortProductName == 'fedora':
        SSG_CONTENT  = "ssg-fedora-ds.xml"
    else:
        SSG_CONTENT = "ssg-%s%s-ds.xml" % (constants.shortProductName,
                                            constants.productVersion.strip(".")[0])

RESULTS_PATH = utils.join_paths(TARGET_CONTENT_DIR,
                                "eval_remediate_results.xml")
REPORT_PATH = utils.join_paths(TARGET_CONTENT_DIR,
                               "eval_remediate_report.html")

PRE_INSTALL_FIX_SYSTEM_ATTR = "urn:redhat:anaconda:pre"

THREAD_FETCH_DATA = "AnaOSCAPdataFetchThread"

SUPPORTED_ARCHIVES = (".zip", ".tar", ".tar.gz", ".tar.bz2", )

# buffer size for reading and writing out data (in bytes)
IO_BUF_SIZE = 2 * 1024 * 1024


class OSCAPaddonError(Exception):
    """Exception class for OSCAP addon related errors."""

    pass


class OSCAPaddonNetworkError(OSCAPaddonError):
    """Exception class for OSCAP addon related network errors."""

    pass


class ExtractionError(OSCAPaddonError):
    """Exception class for the extraction errors."""

    pass


MESSAGE_TYPE_FATAL = 0
MESSAGE_TYPE_WARNING = 1
MESSAGE_TYPE_INFO = 2

# namedtuple for messages returned from the rules evaluation
#   origin -- class (inherited from RuleHandler) that generated the message
#   type -- one of the MESSAGE_TYPE_* constants defined above
#   text -- the actual message that should be displayed, logged, ...
RuleMessage = namedtuple("RuleMessage", ["origin", "type", "text"])


def get_fix_rules_pre(profile, fpath, ds_id="", xccdf_id="", tailoring=""):
    """
    Get fix rules for the pre-installation environment for a given profile in a
    given datastream and checklist in a given file.

    :see: run_oscap_remediate
    :see: _run_oscap_gen_fix
    :return: fix rules for a given profile
    :rtype: str

    """

    return _run_oscap_gen_fix(profile, fpath, PRE_INSTALL_FIX_SYSTEM_ATTR,
                              ds_id=ds_id, xccdf_id=xccdf_id,
                              tailoring=tailoring)


def _run_oscap_gen_fix(profile, fpath, template, ds_id="", xccdf_id="",
                       tailoring=""):
    """
    Run oscap tool on a given file to get the contents of fix elements with the
    'system' attribute equal to a given template for a given datastream,
    checklist and profile.

    :see: run_oscap_remediate
    :param template: the value of the 'system' attribute of the fix elements
    :type template: str
    :return: oscap tool's stdout
    :rtype: str

    """

    if not profile:
        return ""

    args = ["oscap", "xccdf", "generate", "fix"]
    args.append("--template=%s" % template)

    # oscap uses the default profile by default
    if profile.lower() != "default":
        args.append("--profile=%s" % profile)
    if ds_id:
        args.append("--datastream-id=%s" % ds_id)
    if xccdf_id:
        args.append("--xccdf-id=%s" % xccdf_id)
    if tailoring:
        args.append("--tailoring-file=%s" % tailoring)

    args.append(fpath)

    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    except OSError as oserr:
        msg = "Failed to run the oscap tool: %s" % oserr
        raise OSCAPaddonError(msg)

    (stdout, stderr) = proc.communicate()

    messages = re.findall(r'OpenSCAP Error:.*', stderr)
    if messages:
        for message in messages:
            log.warning("OSCAP addon: " + message)

    # pylint thinks Popen has no attribute returncode
    # pylint: disable-msg=E1101
    if proc.returncode != 0:
        msg = "Failed to generate fix rules with the oscap tool: %s" % stderr
        raise OSCAPaddonError(msg)

    return stdout


def run_oscap_remediate(profile, fpath, ds_id="", xccdf_id="", tailoring="",
                        chroot=""):
    """
    Run the evaluation and remediation with the oscap tool on a given file,
    doing the remediation as defined in a given profile defined in a given
    checklist that is a part of a given datastream. If requested, run in
    chroot.

    :param profile: id of the profile that will drive the remediation
    :type profile: str
    :param fpath: path to a file with SCAP content
    :type fpath: str
    :param ds_id: ID of the datastream that contains the checklist defining
                  the profile
    :type ds_id: str
    :param xccdf_id: ID of the checklist that defines the profile
    :type xccdf_id: str
    :param tailoring: path to a tailoring file
    :type tailoring: str
    :param chroot: path to the root the oscap tool should be run in
    :type chroot: str
    :return: oscap tool's stdout (summary of the rules, checks and fixes)
    :rtype: str

    """

    if not profile:
        return ""

    def do_chroot():
        """Helper function doing the chroot if requested."""
        if chroot and chroot != "/":
            os.chroot(chroot)
            os.chdir("/")

    # make sure the directory for the results exists
    results_dir = os.path.dirname(RESULTS_PATH)
    if chroot:
        results_dir = os.path.normpath(chroot + "/" + results_dir)
    utils.ensure_dir_exists(results_dir)

    args = ["oscap", "xccdf", "eval"]
    args.append("--remediate")
    args.append("--results=%s" % RESULTS_PATH)
    args.append("--report=%s" % REPORT_PATH)

    # oscap uses the default profile by default
    if profile.lower() != "default":
        args.append("--profile=%s" % profile)
    if ds_id:
        args.append("--datastream-id=%s" % ds_id)
    if xccdf_id:
        args.append("--xccdf-id=%s" % xccdf_id)
    if tailoring:
        args.append("--tailoring-file=%s" % tailoring)

    args.append(fpath)

    try:
        proc = subprocess.Popen(args,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                preexec_fn=do_chroot)
    except OSError as oserr:
        msg = "Failed to run the oscap tool: %s" % oserr
        raise OSCAPaddonError(msg)

    (stdout, stderr) = proc.communicate()

    messages = re.findall(r'OpenSCAP Error:.*', stderr)
    if messages:
        for message in messages:
            log.warning("OSCAP addon: " + message)

    # save stdout?
    # pylint thinks Popen has no attribute returncode
    # pylint: disable-msg=E1101
    if proc.returncode not in (0, 2):
        # 0 -- success; 2 -- no error, but checks/remediation failed
        msg = "Content evaluation and remediation with the oscap tool "\
            "failed: %s" % stderr
        raise OSCAPaddonError(msg)

    return stdout


def wait_and_fetch_net_data(url, out_file, ca_certs=None):
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

    if not nm.nm_is_connected():
        raise OSCAPaddonNetworkError("Network connection needed to fetch data.")

    fetch_data_thread = AnacondaThread(name=THREAD_FETCH_DATA,
                                       target=fetch_data,
                                       args=(url, out_file, ca_certs),
                                       fatal=False)

    # register and run the thread
    threadMgr.add(fetch_data_thread)

    return THREAD_FETCH_DATA


def extract_data(archive, out_dir, ensure_has_files=None):
    """
    Fuction that extracts the given archive to the given output directory. It
    tries to find out the archive type by the file name.

    :param archive: path to the archive file that should be extracted
    :type archive: str
    :param out_dir: output directory the archive should be extracted to
    :type out_dir: str
    :param ensure_has_files: relative paths to the files that must exist in the
                             archive
    :type ensure_has_files: iterable of strings or None
    :return: a list of files and directories extracted from the archive
    :rtype: [str]

    """

    # get rid of empty file paths
    ensure_has_files = [fpath for fpath in ensure_has_files if fpath]

    if archive.endswith(".zip"):
        # ZIP file
        try:
            zfile = zipfile.ZipFile(archive, "r")
        except zipfile.BadZipfile as err:
            raise ExtractionError(err.message)

        # generator for the paths of the files found in the archive (dirs end
        # with "/")
        files = set(info.filename for info in zfile.filelist
                    if not info.filename.endswith("/"))
        for fpath in ensure_has_files or ():
            if fpath not in files:
                msg = "File '%s' not found in the archive '%s'" % (fpath,
                                                                   archive)
                raise ExtractionError(msg)

        utils.ensure_dir_exists(out_dir)
        zfile.extractall(path=out_dir)
        zfile.close()
        return [utils.join_paths(out_dir, info.filename) for info in zfile.filelist]
    elif archive.endswith(".tar"):
        # plain tarball
        return _extract_tarball(archive, out_dir, ensure_has_files, None)
    elif archive.endswith(".tar.gz"):
        # gzipped tarball
        return _extract_tarball(archive, out_dir, ensure_has_files, "gz")
    elif archive.endswith(".tar.bz2"):
        # bzipped tarball
        return _extract_tarball(archive, out_dir, ensure_has_files, "bz2")
    elif archive.endswith(".rpm"):
        # RPM
        return _extract_rpm(archive, out_dir, ensure_has_files)
    # elif other types of archives
    else:
        raise ExtractionError("Unsuported archive type")


def _extract_tarball(archive, out_dir, ensure_has_files, alg):
    """
    Extract the given TAR archive to the given output directory and make sure
    the given file exists in the archive.

    :see: extract_data
    :param alg: compression algorithm used for the tarball
    :type alg: str (one of "gz", "bz2") or None
    :return: a list of files and directories extracted from the archive
    :rtype: [str]

    """

    if alg and alg not in ("gz", "bz2",):
        raise ExtractionError("Unsupported compression algorithm")

    mode = "r"
    if alg:
        mode += ":%s" % alg

    try:
        tfile = tarfile.TarFile.open(archive, mode)
    except tarfile.TarError as err:
        raise ExtractionError(err.message)

    # generator for the paths of the files found in the archive
    files = set(member.path for member in tfile.getmembers()
                if member.isfile())

    for fpath in ensure_has_files or ():
        if fpath not in files:
            msg = "File '%s' not found in the archive '%s'" % (fpath, archive)
            raise ExtractionError(msg)

    utils.ensure_dir_exists(out_dir)
    tfile.extractall(path=out_dir)
    tfile.close()

    return [utils.join_paths(out_dir, member.path) for member in tfile.getmembers()]


def _extract_rpm(rpm_path, root="/", ensure_has_files=None):
    """
    Extract the given RPM into the directory tree given by the root argument
    and make sure the given file exists in the archive.

    :param rpm_path: path to the RPM file that should be extracted
    :type rpm_path: str
    :param root: root of the directory tree the RPM should be extracted into
    :type root: str
    :param ensure_has_files: relative paths to the files that must exist in the
                             RPM
    :type ensure_has_files: iterable of strings or None
    :return: a list of files and directories extracted from the archive
    :rtype: [str]

    """

    # run rpm2cpio and process the output with the cpioarchive module
    temp_fd, temp_path = tempfile.mkstemp(prefix="oscap_rpm")
    proc = subprocess.Popen(["rpm2cpio", rpm_path], stdout=temp_fd)
    proc.wait()
    if proc.returncode != 0:
        msg = "Failed to convert RPM '%s' to cpio archive" % rpm_path
        raise ExtractionError(msg)

    os.close(temp_fd)

    try:
        archive = cpioarchive.CpioArchive(temp_path)
    except cpioarchive.CpioError as err:
        raise ExtractionError(err.message)

    # get entries from the archive (supports only iteration over entries)
    entries = set(entry for entry in archive)

    # cpio entry names (paths) start with the dot
    entry_names = [entry.name.lstrip(".") for entry in entries]

    for fpath in ensure_has_files or ():
        # RPM->cpio entries have absolute paths
        if fpath not in entry_names and \
           os.path.join("/", fpath) not in entry_names:
            msg = "File '%s' not found in the archive '%s'" % (fpath, rpm_path)
            raise ExtractionError(msg)

    try:
        for entry in entries:
            dirname = os.path.dirname(entry.name.lstrip("."))
            out_dir = os.path.normpath(root + dirname)
            utils.ensure_dir_exists(out_dir)

            out_fpath = os.path.normpath(root + entry.name.lstrip("."))
            if os.path.exists(out_fpath):
                continue
            with open(out_fpath, "wb") as out_file:
                buf = entry.read(IO_BUF_SIZE)
                while buf:
                    out_file.write(buf)
                    buf = entry.read(IO_BUF_SIZE)
    except (IOError, cpioarchive.CpioError) as e:
        raise ExtractionError(e)

    # cleanup
    archive.close()
    os.unlink(temp_path)

    return [os.path.normpath(root + name) for name in entry_names]


def strip_content_dir(fpaths, phase="preinst"):
    """
    Strip content directory prefix from the file paths for either
    pre-installation or post-installation phase.

    :param fpaths: iterable of file paths to strip content directory prefix
                   from
    :type fpaths: iterable of strings
    :param phase: specifies pre-installation or post-installation phase
    :type phase: "preinst" or "postinst"
    :return: the same iterable of file paths as given with the content
             directory prefix stripped
    :rtype: same type as fpaths

    """

    if phase == "preinst":
        remove_prefix = lambda x: x[len(INSTALLATION_CONTENT_DIR):]
    else:
        remove_prefix = lambda x: x[len(TARGET_CONTENT_DIR):]

    return utils.keep_type_map(remove_prefix, fpaths)


def ssg_available(root="/"):
    """
    Tries to find the SCAP Security Guide under the given root.

    :return: True if SSG was found under the given root, False otherwise

    """

    return os.path.exists(utils.join_paths(root, SSG_DIR + SSG_CONTENT))


def dry_run_skip(func):
    """
    Decorator that makes sure the decorated function is noop in the dry-run
    mode.

    :param func: a decorated function that needs to have the first parameter an
                 object with the _addon_data attribute referencing the OSCAP
                 addon's ksdata
    """

    @wraps(func)
    def decorated(self, *args, **kwargs):
        if self._addon_data.dry_run:
            return
        else:
            return func(self, *args, **kwargs)

    return decorated
