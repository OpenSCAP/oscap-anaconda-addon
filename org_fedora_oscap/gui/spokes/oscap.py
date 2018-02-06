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

import threading
import logging
import gettext
from functools import wraps

# the path to addons is in sys.path so we can import things
# from org_fedora_oscap
from org_fedora_oscap import common
from org_fedora_oscap import data_fetch
from org_fedora_oscap import rule_handling
from org_fedora_oscap import content_handling
from org_fedora_oscap import utils
from org_fedora_oscap.common import dry_run_skip
from pyanaconda.threads import threadMgr, AnacondaThread
from pyanaconda.ui.gui.spokes import NormalSpoke
from pyanaconda.ui.communication import hubQ
from pyanaconda.ui.gui.utils import gtk_action_wait, really_hide, really_show
from pyanaconda.ui.gui.utils import set_treeview_selection, fire_gtk_action, GtkActionList
from pyanaconda.ui.categories.system import SystemCategory
from pykickstart.errors import KickstartValueError

# pylint: disable-msg=E0611
from gi.repository import Gdk

log = logging.getLogger("anaconda")
_ = lambda x: gettext.ldgettext("oscap-anaconda-addon", x)
N_ = lambda x: x

# export only the spoke, no helper functions, classes or constants
__all__ = ["OSCAPSpoke"]

# pages in the main notebook
SET_PARAMS_PAGE = 0
GET_CONTENT_PAGE = 1


# helper functions
def set_combo_selection(combo, item, unset_first=False):
    """
    Set selected item of the combobox.

    :return: True if successfully set, False otherwise
    :rtype: bool

    """

    if unset_first:
        combo.set_active_iter(None)

    model = combo.get_model()
    if not model:
        return False

    itr = model.get_iter_first()
    while itr:
        if model[itr][0] == item:
            combo.set_active_iter(itr)
            return True

        itr = model.iter_next(itr)

        return False


def get_combo_selection(combo):
    """
    Get the selected item of the combobox.

    :return: selected item or None

    """

    model = combo.get_model()
    itr = combo.get_active_iter()
    if not itr or not model:
        return None

    return model[itr][0]


def render_message_type(column, renderer, model, itr, user_data=None):
    # get message type from the first column
    value = model[itr][0]

    if value == common.MESSAGE_TYPE_FATAL:
        renderer.set_property("stock-id", "gtk-dialog-error")
    elif value == common.MESSAGE_TYPE_WARNING:
        renderer.set_property("stock-id", "gtk-dialog-warning")
    elif value == common.MESSAGE_TYPE_INFO:
        renderer.set_property("stock-id", "gtk-info")
    else:
        renderer.set_property("stock-id", "gtk-dialog-question")


def set_ready(func):
    @wraps(func)
    def decorated(self, *args, **kwargs):
        ret = func(self, *args, **kwargs)

        self._unitialized_status = None
        self._ready = True
        # pylint: disable-msg=E1101
        hubQ.send_ready(self.__class__.__name__, True)
        hubQ.send_message(self.__class__.__name__, self.status)

        return ret

    return decorated


class OSCAPSpoke(NormalSpoke):
    """
    Main class of the OSCAP addon spoke that will appear in the Security
    category on the Summary hub. It allows interactive choosing of the data
    stream, checklist and profile driving the evaluation and remediation of the
    available SCAP content in the installation process.

    :see: pyanaconda.ui.common.UIObject
    :see: pyanaconda.ui.common.Spoke
    :see: pyanaconda.ui.gui.GUIObject

    """

    # class attributes defined by API #

    # list all top-level objects from the .glade file that should be exposed
    # to the spoke or leave empty to extract everything
    builderObjects = ["OSCAPspokeWindow", "profilesStore", "changesStore",
                      "dsStore", "xccdfStore", "profilesStore",
                      ]

    # the name of the main window widget
    mainWidgetName = "OSCAPspokeWindow"

    # name of the .glade file in the same directory as this source
    uiFile = "oscap.glade"

    # name of the file providing help content for this spoke
    helpFile = "SecurityPolicySpoke.xml"

    # domain of oscap-anaconda-addon translations
    translationDomain = "oscap-anaconda-addon"

    # category this spoke belongs to
    category = SystemCategory

    # spoke icon (will be displayed on the hub)
    # preferred are the -symbolic icons as these are used in Anaconda's spokes
    icon = "changes-prevent-symbolic"

    # title of the spoke (will be displayed on the hub)
    title = N_("_SECURITY POLICY")

    # methods defined by API and helper methods #
    def __init__(self, data, storage, payload, instclass):
        """
        :see: pyanaconda.ui.common.Spoke.__init__
        :param data: data object passed to every spoke to load/store data
                     from/to it
        :type data: pykickstart.base.BaseHandler
        :param storage: object storing storage-related information
                        (disks, partitioning, bootloader, etc.)
        :type storage: blivet.Blivet
        :param payload: object storing packaging-related information
        :type payload: pyanaconda.packaging.Payload
        :param instclass: distribution-specific information
        :type instclass: pyanaconda.installclass.BaseInstallClass

        """

        NormalSpoke.__init__(self, data, storage, payload, instclass)
        self._addon_data = self.data.addons.org_fedora_oscap
        self._storage = storage
        self._ready = False

        # the first status provided
        self._unitialized_status = _("Not ready")

        self._content_handler = None
        self._content_handling_cls = None
        self._ds_checklists = None

        # used for changing profiles, stored as self._addon_data.rule_data when
        # leaving the spoke
        self._rule_data = None

        # used for storing previously set root password if we need to remove it
        # due to the chosen policy (so that we can put it back in case of
        # revert)
        self.__old_root_pw = None

        # used to check if the profile was changed or not
        self._active_profile = None

        # prevent multiple simultaneous data fetches
        self._fetching = False
        self._fetch_flag_lock = threading.Lock()

        self._error = None

        # wait for all Anaconda spokes to initialiuze
        self._anaconda_spokes_initialized = threading.Event()
        self.initialization_controller.init_done.connect(self._all_anaconda_spokes_initialized)

    def _all_anaconda_spokes_initialized(self):
        log.debug("OSCAP addon: Anaconda init_done signal triggered")
        self._anaconda_spokes_initialized.set()

    def initialize(self):
        """
        The initialize method that is called after the instance is created.
        The difference between __init__ and this method is that this may take
        a long time and thus could be called in a separated thread.

        :see: pyanaconda.ui.common.UIObject.initialize

        """

        NormalSpoke.initialize(self)
        column = self.builder.get_object("messageTypeColumn")
        renderer = self.builder.get_object("messageTypeRenderer")
        column.set_cell_data_func(renderer, render_message_type)

        # the main notebook containing two pages -- for settings parameters and
        # for entering content URL
        self._main_notebook = self.builder.get_object("mainNotebook")

        # the store that holds the messages that come from the rules evaluation
        self._message_store = self.builder.get_object("changesStore")

        # stores with data streams, checklists and profiles
        self._ds_store = self.builder.get_object("dsStore")
        self._xccdf_store = self.builder.get_object("xccdfStore")
        self._profiles_store = self.builder.get_object("profilesStore")

        # comboboxes for data streams and checklists
        self._ids_box = self.builder.get_object("idsBox")
        self._ds_combo = self.builder.get_object("dsCombo")
        self._xccdf_combo = self.builder.get_object("xccdfCombo")

        # profiles view and selection
        self._profiles_view = self.builder.get_object("profilesView")
        self._profiles_selection = self.builder.get_object("profilesSelection")
        selected_column = self.builder.get_object("selectedColumn")
        selected_renderer = self.builder.get_object("selectedRenderer")
        selected_column.set_cell_data_func(selected_renderer,
                                           self._render_selected)

        # button for switching profiles
        self._choose_button = self.builder.get_object("chooseProfileButton")

        # toggle switching the dry-run mode
        self._dry_run_switch = self.builder.get_object("dryRunSwitch")

        # control buttons
        self._control_buttons = self.builder.get_object("controlButtons")

        # content URL entering, content fetching, ...
        self._no_content_label = self.builder.get_object("noContentLabel")
        self._content_url_entry = self.builder.get_object("urlEntry")
        self._fetch_button = self.builder.get_object("fetchButton")
        self._progress_box = self.builder.get_object("progressBox")
        self._progress_spinner = self.builder.get_object("progressSpinner")
        self._progress_label = self.builder.get_object("progressLabel")
        self._ssg_button = self.builder.get_object("ssgButton")

        # if no content was specified and SSG is available, use it
        if not self._addon_data.content_type and common.ssg_available():
            self._addon_data.content_type = "scap-security-guide"
            self._addon_data.content_path = common.SSG_DIR + common.SSG_CONTENT

        if not self._addon_data.content_defined:
            # nothing more to be done now, the spoke is ready
            self._ready = True

            # no more being unitialized
            self._unitialized_status = None

            # user is going to enter the content URL
            self._content_url_entry.grab_focus()

            # pylint: disable-msg=E1101
            hubQ.send_ready(self.__class__.__name__, True)
        else:
            # else fetch data
            self._fetch_data_and_initialize()

    def _render_selected(self, column, renderer, model, itr, user_data=None):
        if model[itr][2]:
            renderer.set_property("stock-id", "gtk-apply")
        else:
            renderer.set_property("stock-id", None)

    def _fetch_data_and_initialize(self):
        """Fetch data from a specified URL and initialize everything."""

        with self._fetch_flag_lock:
            if self._fetching:
                # prevent multiple fetches running simultaneously
                return
            self._fetching = True

        thread_name = None
        if any(self._addon_data.content_url.startswith(net_prefix)
               for net_prefix in data_fetch.NET_URL_PREFIXES):
            # need to fetch data over network
            try:
                thread_name = common.wait_and_fetch_net_data(
                                     self._addon_data.content_url,
                                     self._addon_data.raw_preinst_content_path,
                                     self._addon_data.certificates)
            except common.OSCAPaddonNetworkError:
                self._network_problem()
                with self._fetch_flag_lock:
                    self._fetching = False
                return
            except KickstartValueError:
                self._invalid_url()
                with self._fetch_flag_lock:
                    self._fetching = False
                return

        # pylint: disable-msg=E1101
        hubQ.send_message(self.__class__.__name__,
                          _("Fetching content data"))
        # pylint: disable-msg=E1101
        hubQ.send_not_ready(self.__class__.__name__)
        threadMgr.add(AnacondaThread(name="OSCAPguiWaitForDataFetchThread",
                                     target=self._init_after_data_fetch,
                                     args=(thread_name,)))

    @set_ready
    def _init_after_data_fetch(self, wait_for):
        """
        Waits for data fetching to be finished, extracts it (if needed),
        populates the stores and evaluates pre-installation fixes from the
        content and marks the spoke as ready in the end.

        :param wait_for: name of the thread to wait for (if any)
        :type wait_for: str or None

        """

        try:
            threadMgr.wait(wait_for)
        except data_fetch.DataFetchError:
            self._data_fetch_failed()
            with self._fetch_flag_lock:
                self._fetching = False
            return
        finally:
            # stop the spinner in any case
            fire_gtk_action(self._progress_spinner.stop)

        if self._addon_data.fingerprint:
            hash_obj = utils.get_hashing_algorithm(self._addon_data.fingerprint)
            digest = utils.get_file_fingerprint(self._addon_data.raw_preinst_content_path,
                                                hash_obj)
            if digest != self._addon_data.fingerprint:
                self._integrity_check_failed()
                # fetching done
                with self._fetch_flag_lock:
                    self._fetching = False
                return

        # RPM is an archive at this phase
        if self._addon_data.content_type in ("archive", "rpm"):
            # extract the content
            try:
                fpaths = common.extract_data(self._addon_data.raw_preinst_content_path,
                                             common.INSTALLATION_CONTENT_DIR,
                                             [self._addon_data.content_path])
            except common.ExtractionError as err:
                self._extraction_failed(err.message)
                # fetching done
                with self._fetch_flag_lock:
                    self._fetching = False
                return

            # and populate missing fields
            self._content_handling_cls, files = content_handling.explore_content_files(fpaths)
            files = common.strip_content_dir(files)

            # pylint: disable-msg=E1103
            self._addon_data.content_path = self._addon_data.content_path or files.xccdf
            self._addon_data.cpe_path = self._addon_data.cpe_path or files.cpe
            self._addon_data.tailoring_path = (self._addon_data.tailoring_path or
                                               files.tailoring)
        elif self._addon_data.content_type == "datastream":
            self._content_handling_cls = content_handling.DataStreamHandler
        elif self._addon_data.content_type == "scap-security-guide":
            self._content_handling_cls = content_handling.BenchmarkHandler
        else:
            raise common.OSCAPaddonError("Unsupported content type")

        try:
            self._content_handler = self._content_handling_cls(self._addon_data.preinst_content_path,
                                                               self._addon_data.preinst_tailoring_path)
        except content_handling.ContentHandlingError:
            self._invalid_content()
            # fetching done
            with self._fetch_flag_lock:
                self._fetching = False

            return

        if self._using_ds:
            # populate the stores from items from the content
            self._ds_checklists = self._content_handler.get_data_streams_checklists()
            add_ds_ids = GtkActionList()
            add_ds_ids.add_action(self._ds_store.clear)
            for dstream in self._ds_checklists.iterkeys():
                add_ds_ids.add_action(self._add_ds_id, dstream)
            add_ds_ids.fire()

        self._update_ids_visibility()

        # refresh UI elements
        self.refresh()

        # let all initialization and configuration happen before we evaluate
        # the setup
        if not self._anaconda_spokes_initialized.is_set():
            # only wait (and log the messages) if the event is not set yet
            log.debug("OSCAP addon: waiting for all Anaconda spokes to be initialized")
            self._anaconda_spokes_initialized.wait()
            log.debug("OSCAP addon: all Anaconda spokes have been initialized - continuing")

        # try to switch to the chosen profile (if any)
        selected = self._switch_profile()

        if self._addon_data.profile_id and not selected:
            # profile ID given, but it was impossible to select it -> invalid
            # profile ID given
            self._invalid_profile_id()
            return

        # initialize the self._addon_data.rule_data
        self._addon_data.rule_data = self._rule_data

        # update the message store with the messages
        self._update_message_store()

        # all initialized, we can now let user set parameters
        fire_gtk_action(self._main_notebook.set_current_page, SET_PARAMS_PAGE)

        # and use control buttons
        fire_gtk_action(really_show, self._control_buttons)

        # fetching done
        with self._fetch_flag_lock:
            self._fetching = False

        # no error
        self._set_error(None)

    @property
    def _using_ds(self):
        return self._content_handling_cls == content_handling.DataStreamHandler

    @property
    def _current_ds_id(self):
        return get_combo_selection(self._ds_combo)

    @property
    def _current_xccdf_id(self):
        return get_combo_selection(self._xccdf_combo)

    @property
    def _current_profile_id(self):
        store, itr = self._profiles_selection.get_selected()
        if not store or not itr:
            return None
        else:
            return store[itr][0]

    def _add_ds_id(self, ds_id):
        """
        Add data stream ID to the data streams store.

        :param ds_id: data stream ID
        :type ds_id: str

        """

        self._ds_store.append([ds_id])

    @gtk_action_wait
    def _update_ids_visibility(self):
        """
        Updates visibility of the combo boxes that are used to select the DS
        and XCCDF IDs.

        """

        if self._using_ds:
            # only show the combo boxes if there are multiple data streams or
            # multiple xccdfs (IOW if there's something to choose from)
            ds_ids = self._ds_checklists.keys()
            if len(ds_ids) > 1 or len(self._ds_checklists[ds_ids[0]]) > 1:
                really_show(self._ids_box)
                return

        # not showing, hide instead
        really_hide(self._ids_box)

    @gtk_action_wait
    def _update_xccdfs_store(self):
        """
        Clears and repopulates the store with XCCDF IDs from the currently
        selected data stream.

        """

        if self._ds_checklists is None:
            # not initialized, cannot do anything
            return

        self._xccdf_store.clear()
        for xccdf_id in self._ds_checklists[self._current_ds_id]:
            self._xccdf_store.append([xccdf_id])

    @gtk_action_wait
    def _update_profiles_store(self):
        """
        Clears and repopulates the store with profiles from the currently
        selected data stream and checklist.

        """

        if self._content_handler is None:
            # not initialized, cannot do anything
            return

        if self._using_ds and self._ds_checklists is None:
            # not initialized, cannot do anything
            return

        self._profiles_store.clear()

        if self._using_ds:
            profiles = self._content_handler.get_profiles(self._current_ds_id,
                                                          self._current_xccdf_id)
        else:
            # pylint: disable-msg=E1103
            profiles = self._content_handler.profiles

        for profile in profiles:
            profile_markup = '<span weight="bold">%s</span>\n%s' \
                                % (profile.title, profile.description)
            self._profiles_store.append([profile.id,
                                         profile_markup,
                                         profile.id == self._active_profile])

    def _add_message(self, message):
        """
        Add message to the store.

        :param message: message to be added
        :type message: org_fedora_oscap.common.RuleMessage

        """

        self._message_store.append([message.type, message.text])

    @dry_run_skip
    @gtk_action_wait
    def _update_message_store(self, report_only=False):
        """
        Updates the message store with messages from rule evaluation.

        :param report_only: wheter to do changes in configuration or just
                            report
        :type report_only: bool

        """

        self._message_store.clear()

        if not self._rule_data:
            # RuleData instance not initialized, cannot do anything
            return

        messages = self._rule_data.eval_rules(self.data, self._storage,
                                              report_only)
        if not messages:
            # no messages from the rules, add a message informing about that
            if not self._active_profile:
                # because of no profile
                message = common.RuleMessage(self.__class__,
                                             common.MESSAGE_TYPE_INFO,
                                             _("No profile selected"))
            else:
                # because of no pre-inst rules
                message = common.RuleMessage(self.__class__,
                                             common.MESSAGE_TYPE_INFO,
                                             _("No rules for the pre-installation phase"))
            self._add_message(message)

            # nothing more to be done
            return

        self._resolve_rootpw_issues(messages, report_only)
        for msg in messages:
            self._add_message(msg)

    def _resolve_rootpw_issues(self, messages, report_only):
        """Mitigate root password issues (which are not fatal in GUI)"""
        fatal_rootpw_msgs = [msg for msg in messages
                             if msg.origin == rule_handling.PasswdRules and msg.type == common.MESSAGE_TYPE_FATAL]
        if fatal_rootpw_msgs:
            for msg in fatal_rootpw_msgs:
                # cannot just change the message type because it is a namedtuple
                messages.remove(msg)
                messages.append(common.RuleMessage(self.__class__,
                                                   common.MESSAGE_TYPE_WARNING,
                                                   msg.text))
            if not report_only:
                self.__old_root_pw = self.data.rootpw.password
                self.data.rootpw.password = None
                self.__old_root_pw_seen = self.data.rootpw.seen
                self.data.rootpw.seen = False

    def _revert_rootpw_changes(self):
        if self.__old_root_pw is not None:
            self.data.rootpw.password = self.__old_root_pw
            self.data.rootpw.seen = self.__old_root_pw_seen
            self.__old_root_pw = None
            self.__old_root_pw_seen = None

    @gtk_action_wait
    def _unselect_profile(self, profile_id):
        """Unselects the given profile."""

        if not profile_id:
            # no profile specified, nothing to do
            return

        itr = self._profiles_store.get_iter_first()
        while itr:
            if self._profiles_store[itr][0] == profile_id:
                self._profiles_store.set_value(itr, 2, False)
            itr = self._profiles_store.iter_next(itr)

        if self._rule_data:
            # revert changes and clear rule_data (no longer valid)
            self._rule_data.revert_changes(self.data, self._storage)
            self._revert_rootpw_changes()
            self._rule_data = None

        self._active_profile = None

    @gtk_action_wait
    def _select_profile(self, profile_id):
        """Selects the given profile."""

        if not profile_id:
            # no profile specified, nothing to do
            return False

        if self._using_ds:
            ds = self._current_ds_id
            xccdf = self._current_xccdf_id

            if not all((ds, xccdf, profile_id)):
                # something is not set -> do nothing
                return False
        else:
            ds = None
            xccdf = None

        # get pre-install fix rules from the content
        try:
            rules = common.get_fix_rules_pre(profile_id,
                                             self._addon_data.preinst_content_path,
                                             ds, xccdf,
                                             self._addon_data.preinst_tailoring_path)
        except common.OSCAPaddonError:
            self._set_error("Failed to get rules for the profile '%s'" % profile_id)
            return False

        itr = self._profiles_store.get_iter_first()
        while itr:
            if self._profiles_store[itr][0] == profile_id:
                self._profiles_store.set_value(itr, 2, True)
            itr = self._profiles_store.iter_next(itr)

        # parse and store rules with a clean RuleData instance
        self._rule_data = rule_handling.RuleData()
        for rule in rules.splitlines():
            self._rule_data.new_rule(rule)

        # remember the active profile
        self._active_profile = profile_id

        return True

    @gtk_action_wait
    @dry_run_skip
    def _switch_profile(self):
        """Switches to a current selected profile.

        :returns: whether some profile was selected or not

        """

        self._set_error(None)
        profile = self._current_profile_id
        if not profile:
            return False

        self._unselect_profile(self._active_profile)
        ret = self._select_profile(profile)

        # update messages according to the newly chosen profile
        self._update_message_store()

        return ret

    @set_ready
    def _set_error(self, msg):
        """Set or clear error message"""
        if msg:
            self._error = msg
            self.clear_info()
            self.set_error(msg)
        else:
            self._error = None
            self.clear_info()

    @gtk_action_wait
    def _invalid_content(self):
        """Callback for informing user about provided content invalidity."""

        msg = _("Invalid content provided. Enter a different URL, please.")
        self._progress_label.set_markup("<b>%s</b>" % msg)
        self._wrong_content(msg)

    @gtk_action_wait
    def _invalid_url(self):
        """Callback for informing user about provided URL invalidity."""

        msg = _("Invalid or unsupported content URL, please enter a different one.")
        self._progress_label.set_markup("<b>%s</b>" % msg)
        self._wrong_content(msg)

    @gtk_action_wait
    def _data_fetch_failed(self):
        """Adapts the UI if fetching data from entered URL failed"""

        msg = _("Failed to fetch content. Enter a different URL, please.")
        self._progress_label.set_markup("<b>%s</b>" % msg)
        self._wrong_content(msg)

    @gtk_action_wait
    def _network_problem(self):
        """Adapts the UI if network error was encountered during data fetch"""

        msg = _("Network error encountered when fetching data."
                " Please check that network is setup and working.")
        self._progress_label.set_markup("<b>%s</b>" % msg)
        self._wrong_content(msg)

    @gtk_action_wait
    def _integrity_check_failed(self):
        """Adapts the UI if integrity check fails"""

        msg = _("The integrity check of the content failed. Cannot use the content.")
        self._progress_label.set_markup("<b>%s</b>" % msg)
        self._wrong_content(msg)

    @gtk_action_wait
    def _extraction_failed(self, err_msg):
        """Adapts the UI if extracting data from entered URL failed"""

        msg = _("Failed to extract content (%s). Enter a different URL, "
                "please.") % err_msg
        self._progress_label.set_markup("<b>%s</b>" % msg)
        self._wrong_content(msg)

    @gtk_action_wait
    def _wrong_content(self, msg):
        self._addon_data.clear_all()
        really_hide(self._progress_spinner)
        self._fetch_button.set_sensitive(True)
        self._content_url_entry.set_sensitive(True)
        self._content_url_entry.grab_focus()
        self._content_url_entry.select_region(0, -1)
        self._content_handling_cls = None
        self._set_error(msg)

    @gtk_action_wait
    def _invalid_profile_id(self):
        msg = _("Profile with ID '%s' not defined in the content. Select a different profile, please") % self._addon_data.profile_id
        self._set_error(msg)
        self._addon_data.profile_id = None

    @gtk_action_wait
    def _switch_dry_run(self, dry_run):
        self._choose_button.set_sensitive(not dry_run)

        if dry_run:
            # no profile can be selected in the dry-run mode
            self._unselect_profile(self._active_profile)

            # no messages in the dry-run mode
            self._message_store.clear()
            message = common.RuleMessage(self.__class__,
                                         common.MESSAGE_TYPE_INFO,
                                         _("Not applying security policy"))
            self._add_message(message)

            self._set_error(None)
        else:
            # mark the active profile as selected
            self._select_profile(self._active_profile)
            self._update_message_store()

    @gtk_action_wait
    def refresh(self):
        """
        The refresh method that is called every time the spoke is displayed.
        It should update the UI elements according to the contents of
        self.data.

        :see: pyanaconda.ui.common.UIObject.refresh

        """

        if not self._addon_data.content_defined:
            # hide the control buttons
            really_hide(self._control_buttons)

            # provide SSG if available
            if common.ssg_available():
                # show the SSG button and tweak the rest of the line
                # (the label)
                really_show(self._ssg_button)
                # TRANSLATORS: the other choice if SCAP Security Guide is also
                # available
                tip = _(" or enter data stream content or archive URL below:")
            else:
                # hide the SSG button
                really_hide(self._ssg_button)
                tip = _("No content found. Please enter data stream content or "
                        "archive URL below:")

            self._no_content_label.set_text(tip)

            # hide the progress box, no progress now
            with self._fetch_flag_lock:
                if not self._fetching:
                    really_hide(self._progress_box)

                    self._content_url_entry.set_sensitive(True)
                    self._fetch_button.set_sensitive(True)

                    if not self._content_url_entry.get_text():
                        # no text -> no info/warning
                        self._progress_label.set_text("")

            # switch to the page allowing user to enter content URL and fetch
            # it
            self._main_notebook.set_current_page(GET_CONTENT_PAGE)
            self._content_url_entry.grab_focus()

            # nothing more to do here
            return
        else:
            # show control buttons
            really_show(self._control_buttons)

            self._main_notebook.set_current_page(SET_PARAMS_PAGE)

        self._active_profile = self._addon_data.profile_id

        self._update_ids_visibility()

        if self._using_ds:
            if self._addon_data.datastream_id:
                set_combo_selection(self._ds_combo,
                                    self._addon_data.datastream_id,
                                    unset_first=True)
            else:
                try:
                    default_ds = self._ds_checklists.iterkeys().next()
                    set_combo_selection(self._ds_combo, default_ds,
                                        unset_first=True)
                except StopIteration:
                    # no data stream available
                    pass

                if self._addon_data.datastream_id and self._addon_data.xccdf_id:
                    set_combo_selection(self._xccdf_combo,
                                        self._addon_data.xccdf_id,
                                        unset_first=True)
        else:
            # no combobox changes --> need to update profiles store manually
            self._update_profiles_store()

        if self._addon_data.profile_id:
            set_treeview_selection(self._profiles_view,
                                   self._addon_data.profile_id)

        self._rule_data = self._addon_data.rule_data

        self._update_message_store()

    def apply(self):
        """
        The apply method that is called when the spoke is left. It should
        update the contents of self.data with values set in the GUI elements.

        """

        if not self._addon_data.content_defined or not self._active_profile:
            # no errors for no content or no profile
            self._set_error(None)

        # store currently selected values to the addon data attributes
        if self._using_ds:
            self._addon_data.datastream_id = self._current_ds_id
            self._addon_data.xccdf_id = self._current_xccdf_id

        self._addon_data.profile_id = self._active_profile

        self._addon_data.rule_data = self._rule_data

        self._addon_data.dry_run = not self._dry_run_switch.get_active()

    def execute(self):
        """
        The excecute method that is called when the spoke is left. It is
        supposed to do all changes to the runtime environment according to
        the values set in the GUI elements.

        """

        # nothing to do here
        pass

    @property
    def ready(self):
        """
        The ready property that tells whether the spoke is ready (can be
        visited) or not.

        :rtype: bool

        """

        return self._ready

    @property
    def completed(self):
        """
        The completed property that tells whether all mandatory items on the
        spoke are set, or not. The spoke will be marked on the hub as completed
        or uncompleted acording to the returned value.

        :rtype: bool

        """

        # no error message in the store
        return not self._error and all(row[0] != common.MESSAGE_TYPE_FATAL
                                       for row in self._message_store)

    @property
    @gtk_action_wait
    def status(self):
        """
        The status property that is a brief string describing the state of the
        spoke. It should describe whether all values are set and if possible
        also the values themselves. The returned value will appear on the hub
        below the spoke's title.

        :rtype: str

        """

        if self._error:
            return _("Error fetching and loading content")

        if self._unitialized_status:
            # not initialized
            return self._unitialized_status

        if not self._addon_data.content_defined:
            return _("No content found")

        if not self._active_profile:
            return _("No profile selected")

        # update message store, something may changed from the last update
        self._update_message_store(report_only=True)

        warning_found = False
        for row in self._message_store:
            if row[0] == common.MESSAGE_TYPE_FATAL:
                return _("Misconfiguration detected")
            elif row[0] == common.MESSAGE_TYPE_WARNING:
                warning_found = True

        # TODO: at least the last two status messages need a better wording
        if warning_found:
            return _("Warnings appeared")

        return _("Everything okay")

    def on_ds_combo_changed(self, *args):
        """Handler for the datastream ID change."""

        ds_id = self._current_ds_id
        if not ds_id:
            return

        self._update_xccdfs_store()
        first_checklist = self._ds_checklists[ds_id][0]

        set_combo_selection(self._xccdf_combo, first_checklist)

    def on_xccdf_combo_changed(self, *args):
        """Handler for the XCCDF ID change."""

        # may take a while
        self._update_profiles_store()

    @dry_run_skip
    def on_profiles_selection_changed(self, *args):
        """Handler for the profile selection change."""

        cur_profile = self._current_profile_id
        if cur_profile:
            if cur_profile != self._active_profile:
                # new profile selected, make the selection button sensitive
                self._choose_button.set_sensitive(True)
            else:
                # current active profile selected
                self._choose_button.set_sensitive(False)

    @dry_run_skip
    def on_profile_clicked(self, widget, event, *args):
        """Handler for the profile being clicked on."""

        # if a profile is double-clicked, we should switch to it
        if event.type == Gdk.EventType._2BUTTON_PRESS:
            self._switch_profile()

            # active profile selected
            self._choose_button.set_sensitive(False)

        # let the other actions hooked to the click happen as well
        return False

    def on_profile_chosen(self, *args):
        """
        Handler for the profile being chosen
        (e.g. "Select profile" button hit).

        """

        # switch profile
        self._switch_profile()

        # active profile selected
        self._choose_button.set_sensitive(False)

    def on_fetch_button_clicked(self, *args):
        """Handler for the Fetch button"""

        with self._fetch_flag_lock:
            if self._fetching:
                # some other fetching/pre-processing running, give up
                return

        # prevent user from changing the URL in the meantime
        self._content_url_entry.set_sensitive(False)
        self._fetch_button.set_sensitive(False)
        url = self._content_url_entry.get_text()
        really_show(self._progress_box)
        really_show(self._progress_spinner)

        if not data_fetch.can_fetch_from(url):
            msg = _("Invalid or unsupported URL")
            # cannot start fetching
            self._progress_label.set_markup("<b>%s</b>" % msg)
            self._wrong_content(msg)
            return

        self._progress_label.set_text(_("Fetching content..."))
        self._progress_spinner.start()
        self._addon_data.content_url = url
        if url.endswith(".rpm"):
            self._addon_data.content_type = "rpm"
        elif any(url.endswith(arch_type) for arch_type in common.SUPPORTED_ARCHIVES):
            self._addon_data.content_type = "archive"
        else:
            self._addon_data.content_type = "datastream"

        self._fetch_data_and_initialize()

    def on_dry_run_toggled(self, switch, *args):
        dry_run = not switch.get_active()
        self._addon_data.dry_run = dry_run
        self._switch_dry_run(dry_run)

    def on_change_content_clicked(self, *args):
        self._unselect_profile(self._active_profile)
        self._addon_data.clear_all()
        self.refresh()

    def on_use_ssg_clicked(self, *args):
        self._addon_data.clear_all()
        self._addon_data.content_type = "scap-security-guide"
        self._addon_data.content_path = common.SSG_DIR + common.SSG_CONTENT
        self._fetch_data_and_initialize()
