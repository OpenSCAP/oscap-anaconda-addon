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
Module with various classes and functions needed by the OSCAP addon that are not
specific to any installation mode (tui, gui, ks).

"""

import os
import os.path
import subprocess

from pyanaconda import constants
from pyanaconda import nm
from pyanaconda.threads import threadMgr, AnacondaThread

from org_fedora_oscap import utils
from org_fedora_oscap.data_fetch import fetch_data

# everything else should be private
__all__ = ["run_oscap_remediate", "get_fix_rules_pre"]

INSTALLATION_CONTENT_DIR = "/tmp/openscap_data"
INSTALLATION_CONTENT_DS_FILE = "installation_ds.xml"

RESULTS_PATH = "/root/openscap_data/eval_remediate_results.xml"

PRE_INSTALL_FIX_SYSTEM_ATTR = "urn:redhat:anaconda:pre"

THREAD_FETCH_DATA = "AnaOSCAPdataFetchThread"

class OSCAPaddonError(Exception):
    """Exception class for OSCAP addon related errors."""

    pass

class OSCAPaddonNetworkError(OSCAPaddonError):
    """Exception class for OSCAP addon related network errors."""

    pass

def get_fix_rules_pre(profile, fpath, ds_id="", xccdf_id=""):
    """
    Get fix rules for the pre-installation environment for a given profile in a
    given datastream and checklist in a given file.

    :see: run_oscap_remediate
    :see: _run_oscap_gen_fix
    :return: fix rules for a given profile
    :rtype: str

    """

    return _run_oscap_gen_fix(profile, fpath, PRE_INSTALL_FIX_SYSTEM_ATTR,
                              ds_id=ds_id, xccdf_id=xccdf_id)

def _run_oscap_gen_fix(profile, fpath, template, ds_id="", xccdf_id=""):
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

    args = ["oscap", "xccdf", "generate", "fix"]
    args.append("--profile=%s" % profile)
    args.append("--template=%s" % template)

    if ds_id:
        args.append("--datastream-id=%s" % ds_id)
    if xccdf_id:
        args.append("--xccdf-id=%s" % xccdf_id)

    args.append(fpath)

    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    except OSError as oserr:
        msg = "Failed to run the oscap tool: %s" % oserr
        raise OSCAPaddonError(msg)

    (stdout, stderr) = proc.communicate()

    # pylint thinks Popen has no attribute returncode
    # pylint: disable-msg=E1101
    if proc.returncode != 0 or stderr:
        msg = "Failed to generate fix rules with the oscap tool: %s" % stderr
        raise OSCAPaddonError(msg)

    return stdout

def run_oscap_remediate(profile, fpath, ds_id="", xccdf_id="", chroot=""):
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
    :param chroot: path to the root the oscap tool should be run in
    :type chroot: str
    :return: oscap tool's stdout (summary of the rules, checks and fixes)
    :rtype: str

    """

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
    args.append("--profile=%s" % profile)

    if ds_id:
        args.append("--datastream-id=%s" % ds_id)
    if xccdf_id:
        args.append("--xccdf-id=%s" % xccdf_id)

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

    # save stdout?
    # XXX: is checking return code enough?
    # pylint thinks Popen has no attribute returncode
    # pylint: disable-msg=E1101
    if proc.returncode != 0 or stderr:
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
                                       args=(url, out_file, ca_certs))

    # register and run the thread
    threadMgr.add(fetch_data_thread)

    return THREAD_FETCH_DATA
