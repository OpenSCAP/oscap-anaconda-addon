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
# will never be translated
_ = lambda x: x
N_ = lambda x: x

# the path to addons is in sys.path so we can import things from org_fedora_oscap
from org_fedora_oscap.gui.categories.security import SecurityCategory
from pyanaconda.ui.gui.spokes import NormalSpoke

# export only the spoke, no helper functions, classes or constants
__all__ = ["OSCAPSpoke"]

MESSAGE_TYPE_FATAL = 0
MESSAGE_TYPE_WARNING = 1

def render_message_type(column, renderer, model, itr, user_data=None):
    #get message type from the first column
    value = model[itr][0]

    if value == MESSAGE_TYPE_FATAL:
        renderer.set_property("stock-id", "gtk-dialog-error")
    elif value == MESSAGE_TYPE_WARNING:
        renderer.set_property("stock-id", "gtk-dialog-warning")
    else:
        renderer.set_property("stock-id", "gtk-dialog-question")

class OSCAPSpoke(NormalSpoke):
    """
    Class for the Hello world spoke. This spoke will be in the Hello world
    category and thus on the Summary hub. It is a very simple example of
    a unit for the Anaconda's graphical user interface.

    :see: pyanaconda.ui.common.UIObject
    :see: pyanaconda.ui.common.Spoke
    :see: pyanaconda.ui.gui.GUIObject

    """

    ### class attributes defined by API ###

    # list all top-level objects from the .glade file that should be exposed
    # to the spoke or leave empty to extract everything
    builderObjects = ["OSCAPspokeWindow", "profilesStore", "changesStore"]

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

    ### methods defined by API ###
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

    def refresh(self):
        """
        The refresh method that is called every time the spoke is displayed.
        It should update the UI elements according to the contents of
        self.data.

        :see: pyanaconda.ui.common.UIObject.refresh

        """

        pass

    def apply(self):
        """
        The apply method that is called when the spoke is left. It should
        update the contents of self.data with values set in the GUI elements.

        """

        pass

    def execute(self):
        """
        The excecute method that is called when the spoke is left. It is
        supposed to do all changes to the runtime environment according to
        the values set in the GUI elements.

        """

        # nothing to do here
        pass

    @property
    def completed(self):
        """
        The completed property that tells whether all mandatory items on the
        spoke are set, or not. The spoke will be marked on the hub as completed
        or uncompleted acording to the returned value.

        :rtype: bool

        """

        return False

    @property
    def status(self):
        """
        The status property that is a brief string describing the state of the
        spoke. It should describe whether all values are set and if possible
        also the values themselves. The returned value will appear on the hub
        below the spoke's title.

        :rtype: str

        """

        return _("Misconfiguration detected")
