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

# TODO: enable translations
_ = lambda x: x
N_ = lambda x: x

# the path to addons is in sys.path so we can import things
# from org_fedora_oscap
from org_fedora_oscap.gui.categories.security import SecurityCategory
from org_fedora_oscap import common
from org_fedora_oscap import data_fetch
from org_fedora_oscap import rule_handling
from org_fedora_oscap import content_handling
from org_fedora_oscap import utils

from pyanaconda.threads import threadMgr, AnacondaThread
from pyanaconda.ui.gui.spokes import NormalSpoke
from pyanaconda.ui.communication import hubQ
from pyanaconda.ui.gui.utils import gtk_action_wait, really_hide, really_show

# pylint: disable-msg=E0611
from gi.repository import Gdk

# export only the spoke, no helper functions, classes or constants
__all__ = ["OSCAPSpoke"]

# pages in the main notebook
SET_PARAMS_PAGE = 0
GET_CONTENT_PAGE = 1

# helper functions
def set_combo_selection(combo, item):
    """
    Set selected item of the combobox.

    :return: True if successfully set, False otherwise
    :rtype: bool

    """

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

def set_treeview_selection(treeview, item, col=0):
    """
    Select the given item in the given treeview and scroll to it.

    :param treeview: treeview to select and item in
    :type treeview: GtkTreeView
    :param item: item to be selected
    :type item: str
    :param col: column to search for the item in
    :type col: int
    :return: if successfully selected or not
    :rtype: bool

    """

    model = treeview.get_model()
    itr = model.get_iter_first()
    while itr and not model[itr][col] == item:
        itr = model.iter_next(itr)

    if not itr:
        # item not found, cannot be selected
        return False

    # otherwise select the item and scroll to it
    selection = treeview.get_selection()
    selection.select_iter(itr)
    path = model.get_path(itr)
    treeview.scroll_to_cell(path)
    return True

# TODO: should go "upstream" (to the pyanaconda.ui.gui.utils module)
def fire_gtk_action(func, args=None):
    @gtk_action_wait
    def gtk_action():
        fargs = args or tuple()
        func(*fargs)

    gtk_action()

def render_message_type(column, renderer, model, itr, user_data=None):
    #get message type from the first column
    value = model[itr][0]

    if value == common.MESSAGE_TYPE_FATAL:
        renderer.set_property("stock-id", "gtk-dialog-error")
    elif value == common.MESSAGE_TYPE_WARNING:
        renderer.set_property("stock-id", "gtk-dialog-warning")
    elif value == common.MESSAGE_TYPE_INFO:
        renderer.set_property("stock-id", "gtk-info")
    else:
        renderer.set_property("stock-id", "gtk-dialog-question")

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

    ### class attributes defined by API ###

    # list all top-level objects from the .glade file that should be exposed
    # to the spoke or leave empty to extract everything
    builderObjects = ["OSCAPspokeWindow", "profilesStore", "changesStore",
                      "dsStore", "xccdfStore", "profilesStore",
                      ]

    # the name of the main window widget
    mainWidgetName = "OSCAPspokeWindow"

    # name of the .glade file in the same directory as this source
    uiFile = "oscap.glade"

    # category this spoke belongs to
    category = SecurityCategory

    # spoke icon (will be displayed on the hub)
    # preferred are the -symbolic icons as these are used in Anaconda's spokes
    icon = "changes-prevent-symbolic"

    # title of the spoke (will be displayed on the hub)
    title = N_("_SECURITY PROFILE")

    ### methods defined by API and helper methods ###
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

        # used to check if the profile was changed or not
        self._active_profile = None

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
        selected_column.set_cell_data_func(selected_renderer, self._render_selected)

        # button for switching profiles
        self._choose_button = self.builder.get_object("chooseProfileButton")

        # content URL entering, content fetching, ...
        self._content_url_entry = self.builder.get_object("urlEntry")
        self._fetch_button = self.builder.get_object("fetchButton")
        self._progress_box = self.builder.get_object("progressBox")
        self._progress_spinner = self.builder.get_object("progressSpinner")
        self._progress_label = self.builder.get_object("progressLabel")

        if not self._addon_data.content_url:
            # switch  to the page allowing user to enter content URL and fetch it
            self._main_notebook.set_current_page(GET_CONTENT_PAGE)

            # hide the progress box, no progress now
            really_hide(self._progress_box)

            # nothing more to be done now, the spoke is ready
            self._ready = True

            # no more being unitialized
            self._unitialized_status = None

            # user is going to enter the content URL
            self._content_url_entry.grab_focus()

            # pylint: disable-msg=E1101
            hubQ.send_ready(self.__class__.__name__, True)
        else:
            self._main_notebook.set_current_page(SET_PARAMS_PAGE)
            # else fetch data
            self._fetch_data_and_initialize()

    def _render_selected(self, column, renderer, model, itr, user_data=None):
        if model[itr][2]:
            renderer.set_property("stock-id", "gtk-apply")
        else:
            renderer.set_property("stock-id", None)

    def _fetch_data_and_initialize(self):
        """Fetch data from a specified URL and initialize everything."""

        thread_name = None
        if any(self._addon_data.content_url.startswith(net_prefix)
               for net_prefix in data_fetch.NET_URL_PREFIXES):
            # need to fetch data over network
            thread_name = common.wait_and_fetch_net_data(
                                     self._addon_data.content_url,
                                     self._addon_data.raw_preinst_content_path,
                                     self._addon_data.certificates)

        # pylint: disable-msg=E1101
        hubQ.send_message(self.__class__.__name__,
                          _("Fetching content data"))
        # pylint: disable-msg=E1101
        hubQ.send_not_ready(self.__class__.__name__)
        threadMgr.add(AnacondaThread(name="OSCAPguiWaitForDataFetchThread",
                                     target=self._init_after_data_fetch,
                                     args=(thread_name,)))

    def _init_after_data_fetch(self, thread_name):
        """
        Waits for data fetching to be finished, extracts it (if needed),
        populates the stores and evaluates pre-installation fixes from the
        content and marks the spoke as ready in the end.

        :param thread_name: name of the thread to wait for (if any)
        :type thread_name: str or None

        """

        try:
            fetch_thread = threadMgr.wait(thread_name)
        except:
            self._data_fetch_failed()
            return
        finally:
            # stop the spinner in any case
            fire_gtk_action(self._progress_spinner.stop)

        if self._addon_data.fingerprint:
            hash_obj = utils.get_hashing_algorithm(self._addon_data.fingerprint)
            digest = utils.get_file_fingerprint(self._addon_data.raw_preinst_content,
                                                hash_obj)
            if digest != self._addon_data.fingerprint:
                msg = _("Integrity check failed")
                raise content_handling.ContentCheckError(msg)

        # RPM is an archive at this phase
        if self._addon_data.content_type in ("archive", "rpm"):
            # extract the content and populate missing fields
            fpaths = common.extract_data(self._addon_data.raw_preinst_content_path,
                                         common.INSTALLATION_CONTENT_DIR,
                                         [self._addon_data.xccdf_path])
            self._content_handling_cls, files = \
                                 content_handling.explore_content_files(fpaths)
            files = common.strip_content_dir(files)

            # pylint: disable-msg=E1103
            self._addon_data.xccdf_path = self._addon_data.xccdf_path or files.xccdf
            self._addon_data.cpe_path = self._addon_data.cpe_path or files.cpe
            self._addon_data.tailoring_path = (self._addon_data.tailoring_path or
                                               files.tailoring)
        elif self._addon_data.content_type == "datastream":
            self._content_handling_cls = content_handling.DataStreamHandler
        else:
            raise common.OSCAPaddonError("Unsupported content type")

        try:
            self._content_handler = self._content_handling_cls(\
                                      self._addon_data.preinst_content_path,
                                      self._addon_data.preinst_tailoring_path)
        except content_handling.ContentHandlingError:
            self._invalid_content()
            return

        if self._using_ds:
            # populate the stores from items from the content
            self._ds_checklists = self._content_handler.get_data_streams_checklists()
            for dstream in self._ds_checklists.iterkeys():
                self._add_ds_id(dstream)
        else:
            # hide the labels and comboboxes for datastream-id and xccdf-id
            # selection
            fire_gtk_action(really_hide, (self._ids_box,))

        # refresh UI elements
        self.refresh()

        # try to switch to the chosen profile (if any)
        self._switch_profile()

        # initialize the self._addon_data.rule_data
        self._addon_data.rule_data = self._rule_data

        # no more being unitialized
        self._unitialized_status = None
        self._ready = True

        # all initialized, we can now let user set parameters
        self._main_notebook.set_current_page(SET_PARAMS_PAGE)

        # pylint: disable-msg=E1101
        hubQ.send_ready(self.__class__.__name__, True)
        hubQ.send_message(self.__class__.__name__, self.status)

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

    def _update_message_store(self, report_only=False):
        """
        Updates the message store with messages from rule evaluation.

        :param report_only: wheter to do changes in configuration or just report
        :type report_only: bool

        """

        if not self._rule_data:
            # RuleData instance not initialized, cannot do anything
            return

        self._message_store.clear()

        messages = self._rule_data.eval_rules(self.data, self._storage,
                                              report_only)
        if not messages:
            # no messages from the rules, add a message informing about that
            if not self._active_profile:
                # because of no profile
                message = common.RuleMessage(common.MESSAGE_TYPE_INFO,
                                           _("No profile selected"))
            else:
                # because of no pre-inst rules
                message = common.RuleMessage(common.MESSAGE_TYPE_INFO,
                              _("No rules for the pre-installation phase"))
            self._add_message(message)

            # nothing more to be done
            return

        for msg in messages:
            self._add_message(msg)

    @gtk_action_wait
    def _switch_profile(self):
        """Switches to a current selected profile."""

        def toggle_profiles_selected(store, profile_ids):
            itr = store.get_iter_first()
            while itr:
                if store[itr][0] in profile_ids:
                    store.set_value(itr, 2, not store[itr][2])
                itr = store.iter_next(itr)

        profile = self._current_profile_id
        if not profile:
            return

        if self._using_ds:
            ds = self._current_ds_id
            xccdf = self._current_xccdf_id

            if not all((ds, xccdf, profile)):
                # something is not set -> do nothing
                return
        else:
            ds = None
            xccdf = None
            if not profile:
                # profile not set -> do nothing
                return

        # make the newly chosen profile visually selected
        toggle_profiles_selected(self._profiles_store,
                                 [profile, self._active_profile])

        # revert changes done by the previous profile
        if self._rule_data:
            self._rule_data.revert_changes(self.data, self._storage)

        # get pre-install fix rules from the content
        rules = common.get_fix_rules_pre(profile,
                                         self._addon_data.preinst_content_path,
                                         ds, xccdf,
                                         self._addon_data.preinst_tailoring_path)

        # parse and store rules with a clean RuleData instance
        self._rule_data = rule_handling.RuleData()
        for rule in rules.splitlines():
            self._rule_data.new_rule(rule)

        self._update_message_store()

        # make the selection button insensitive and remember the active profile
        self._choose_button.set_sensitive(False)
        self._active_profile = self._current_profile_id

    @gtk_action_wait
    def _invalid_content(self):
        """Callback for informing user about provided content invalidity."""

        self._progress_label.set_markup("<b>%s</b>" % _("Invalid content "
                                        "provided. Enter a different URL, "
                                        "please."))
        self._wrong_content()

    @gtk_action_wait
    def _data_fetch_failed(self):
        """Adapts the UI if fetching data from entered URL failed"""

        self._progress_label.set_markup("<b>%s</b>" % _("Failed to fetch "
                                        "content. Enter a different URL, "
                                        "please."))
        self._wrong_content()

    @gtk_action_wait
    def _wrong_content(self):
        self._addon_data.content_url = ""
        self._addon_data.content_type = ""
        really_hide(self._progress_spinner)
        self._content_url_entry.grab_focus()
        self._content_url_entry.select_region(0, -1)

    @gtk_action_wait
    def refresh(self):
        """
        The refresh method that is called every time the spoke is displayed.
        It should update the UI elements according to the contents of
        self.data.

        :see: pyanaconda.ui.common.UIObject.refresh

        """

        if not self._addon_data.content_url:
            if not self._content_url_entry.get_text():
                # no text -> no info/warning
                self._progress_label.set_text("")

            self._content_url_entry.grab_focus()

            # nothing more to do here
            return

        if self._using_ds:
            if self._addon_data.datastream_id:
                set_combo_selection(self._ds_combo,
                                    self._addon_data.datastream_id)
            else:
                try:
                    default_ds = self._ds_checklists.iterkeys().next()
                    set_combo_selection(self._ds_combo, default_ds)
                except StopIteration:
                    # no data stream available
                    pass

                if self._addon_data.datastream_id and self._addon_data.xccdf_id:
                    set_combo_selection(self._xccdf_combo,
                                        self._addon_data.xccdf_id)
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

        # store currently selected values to the addon data attributes
        if self._using_ds:
            self._addon_data.datastream_id = self._current_ds_id
            self._addon_data.xccdf_id = self._current_xccdf_id

        self._addon_data.profile_id = self._active_profile

        self._addon_data.rule_data = self._rule_data

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
        return all(row[0] != common.MESSAGE_TYPE_FATAL
                   for row in self._message_store)

    @property
    def status(self):
        """
        The status property that is a brief string describing the state of the
        spoke. It should describe whether all values are set and if possible
        also the values themselves. The returned value will appear on the hub
        below the spoke's title.

        :rtype: str

        """

        if self._unitialized_status:
            # not initialized
            return self._unitialized_status

        if not self._addon_data.content_url:
            return _("No content found")

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

        self._update_xccdfs_store()

        ds_id = self._current_ds_id
        first_checklist = self._ds_checklists[ds_id][0]

        set_combo_selection(self._xccdf_combo, first_checklist)

    def on_xccdf_combo_changed(self, *args):
        """Handler for the XCCDF ID change."""

        # may take a while
        self._update_profiles_store()

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

    def on_profile_clicked(self, widget, event, *args):
        """Handler for the profile being clicked on."""

        # if a profile is double-clicked, we should switch to it
        if event.type == Gdk.EventType._2BUTTON_PRESS:
            self._switch_profile()

        # let the other actions hooked to the click happen as well
        return False

    def on_profile_chosen(self, *args):
        """
        Handler for the profile being chosen (e.g. "Select profile" button hit).

        """

        # switch profile
        self._switch_profile()

    def on_fetch_button_clicked(self, *args):
        """Handler for the Fetch button"""

        url = self._content_url_entry.get_text()
        really_show(self._progress_box)
        really_show(self._progress_spinner)

        if not data_fetch.can_fetch_from(url):
            # cannot start fetching
            really_hide(self._progress_spinner)
            self._progress_label.set_markup("<b>%s</b>" % _("Invalid or unsupported URL"))
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
