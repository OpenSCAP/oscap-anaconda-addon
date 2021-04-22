#
# Copyright (C) 2020 Red Hat, Inc.
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
from dasbus.server.interface import dbus_interface
from dasbus.server.property import emits_properties_changed
from dasbus.typing import *  # pylint: disable=wildcard-import

from pyanaconda.modules.common.base import KickstartModuleInterface

from org_fedora_oscap.constants import OSCAP
from org_fedora_oscap.structures import PolicyData

__all__ = ["OSCAPInterface"]


@dbus_interface(OSCAP.interface_name)
class OSCAPInterface(KickstartModuleInterface):
    """The DBus interface of the OSCAP service."""

    def connect_signals(self):
        super().connect_signals()
        self.watch_property("PolicyEnabled", self.implementation.policy_enabled_changed)
        self.watch_property("PolicyData", self.implementation.policy_data_changed)

    @property
    def PolicyEnabled(self) -> Bool:
        """Is the security policy enabled?

        :return: True or False
        """
        return self.implementation.policy_enabled

    @PolicyEnabled.setter
    @emits_properties_changed
    def PolicyEnabled(self, value: Bool):
        """Should be the security policy enabled?

        :param value: True or False
        """
        self.implementation.policy_enabled = value

    @property
    def PolicyData(self) -> Structure:
        """The security policy data.

        :return: a structure defined by the PolicyData class
        """
        return PolicyData.to_structure(self.implementation.policy_data)

    @PolicyData.setter
    @emits_properties_changed
    def PolicyData(self, value: Structure):
        """Set the security policy data.

        :param value: a structure defined by the PolicyData class
        """
        self.implementation.policy_data = PolicyData.from_structure(value)
