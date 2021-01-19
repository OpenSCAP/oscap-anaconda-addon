#
# Copyright (C) 2021  Red Hat, Inc.
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
import pytest

from unittest.mock import Mock
from dasbus.typing import get_native, get_variant, Str
from pyanaconda.core.constants import REQUIREMENT_TYPE_PACKAGE
from pyanaconda.modules.common.containers import TaskContainer
from pyanaconda.modules.common.structures.requirement import Requirement

from org_fedora_oscap.constants import OSCAP
from org_fedora_oscap.service import installation
from org_fedora_oscap.service.oscap import OSCAPService
from org_fedora_oscap.service.oscap_interface import OSCAPInterface
from org_fedora_oscap.structures import PolicyData


class PropertiesChangedCallback(Mock):

    def __call__(self, interface, changed, invalid):
        return super().__call__(interface, get_native(changed), invalid)

    def assert_call(self, property_name, value):
        self.assert_called_once_with(
            OSCAP.interface_name,
            {property_name: get_native(value)},
            []
        )


@pytest.fixture()
def service():
    return OSCAPService()


@pytest.fixture()
def interface(service):
    return OSCAPInterface(service)


@pytest.fixture
def callback(interface):
    callback = PropertiesChangedCallback()
    interface.PropertiesChanged.connect(callback)
    return callback


@pytest.fixture(autouse=True)
def object_publisher(monkeypatch):
    # Mock any publishing of DBus objects.
    monkeypatch.setattr("pyanaconda.core.dbus.DBus.publish_object", Mock())


def test_policy_enabled(interface: OSCAPInterface, callback):
    policy_enabled = False
    interface.PolicyEnabled = policy_enabled

    callback.assert_call("PolicyEnabled", policy_enabled)
    assert interface.PolicyEnabled == policy_enabled


def test_policy_data(interface: OSCAPInterface, callback):
    policy_structure = {
        "content-type": get_variant(Str, "datastream"),
        "content-url": get_variant(Str, "https://example.com/hardening.xml"),
        "datastream-id": get_variant(Str, "id_datastream_1"),
        "xccdf-id": get_variant(Str, "id_xccdf_new"),
        "profile-id": get_variant(Str, "Web Server"),
        "content-path": get_variant(Str, "/usr/share/oscap/testing_ds.xml"),
        "cpe-path": get_variant(Str, "/usr/share/oscap/cpe.xml"),
        "tailoring-path": get_variant(Str, "/usr/share/oscap/tailoring.xml"),
        "fingerprint": get_variant(Str, "240f2f18222faa98856c3b4fc50c4195"),
        "certificates": get_variant(Str, "/usr/share/oscap/cacert.pem")
    }
    interface.PolicyData = policy_structure

    callback.assert_call("PolicyData", policy_structure)
    assert interface.PolicyData == policy_structure


def test_default_requirements(interface: OSCAPInterface):
    assert interface.CollectRequirements() == []


def test_no_requirements(service: OSCAPService, interface: OSCAPInterface):
    service.policy_enabled = True
    service.policy_data = PolicyData()
    assert interface.CollectRequirements() == []


def test_datastream_requirements(service: OSCAPService, interface: OSCAPInterface):
    data = PolicyData()
    data.content_type = "datastream"
    data.profile_id = "Web Server"

    service.policy_enabled = True
    service.policy_data = data

    requirements = Requirement.from_structure_list(
        interface.CollectRequirements()
    )

    assert len(requirements) == 2
    assert requirements[0].type == REQUIREMENT_TYPE_PACKAGE
    assert requirements[0].name == "openscap"
    assert requirements[1].type == REQUIREMENT_TYPE_PACKAGE
    assert requirements[1].name == "openscap-scanner"


def test_scap_security_guide_requirements(service: OSCAPService, interface: OSCAPInterface):
    data = PolicyData()
    data.content_type = "scap-security-guide"
    data.profile_id = "Web Server"

    service.policy_enabled = True
    service.policy_data = data

    requirements = Requirement.from_structure_list(
        interface.CollectRequirements()
    )

    assert len(requirements) == 3
    assert requirements[0].type == REQUIREMENT_TYPE_PACKAGE
    assert requirements[0].name == "openscap"
    assert requirements[1].type == REQUIREMENT_TYPE_PACKAGE
    assert requirements[1].name == "openscap-scanner"
    assert requirements[2].type == REQUIREMENT_TYPE_PACKAGE
    assert requirements[2].name == "scap-security-guide"


def test_configure_with_no_tasks(interface: OSCAPInterface):
    object_paths = interface.ConfigureWithTasks()
    assert len(object_paths) == 0


def test_configure_with_tasks(service: OSCAPService, interface: OSCAPInterface):
    data = PolicyData()
    data.content_type = "scap-security-guide"
    data.profile_id = "Web Server"

    service.policy_enabled = True
    service.policy_data = data

    object_paths = interface.ConfigureWithTasks()
    assert len(object_paths) == 3

    tasks = TaskContainer.from_object_path_list(object_paths)
    assert isinstance(tasks[0], installation.FetchContentTask)
    assert isinstance(tasks[1], installation.CheckFingerprintTask)
    assert isinstance(tasks[2], installation.EvaluateRulesTask)


def test_install_with_no_tasks(interface: OSCAPInterface):
    object_paths = interface.InstallWithTasks()
    assert len(object_paths) == 0


def test_install_with_tasks(service: OSCAPService, interface: OSCAPInterface):
    data = PolicyData()
    data.content_type = "scap-security-guide"
    data.profile_id = "Web Server"

    service.policy_enabled = True
    service.policy_data = data

    object_paths = interface.InstallWithTasks()
    assert len(object_paths) == 2

    tasks = TaskContainer.from_object_path_list(object_paths)
    assert isinstance(tasks[0], installation.InstallContentTask)
    assert isinstance(tasks[1], installation.RemediateSystemTask)


def test_cancel_tasks(service: OSCAPService):
    data = PolicyData()
    data.content_type = "scap-security-guide"
    data.profile_id = "Web Server"

    service.policy_enabled = True
    service.policy_data = data

    # Collect all tasks.
    tasks = service.configure_with_tasks() + service.install_with_tasks()

    # No task is canceled by default.
    for task in tasks:
        assert task.check_cancel() is False

    callback = Mock()
    service.installation_canceled.connect(callback)

    # The first task should fail with the given data.
    with pytest.raises(Exception):
        tasks[0].run_with_signals()

    # That should cancel all tasks.
    callback.assert_called_once()

    for task in tasks:
        assert task.check_cancel() is True
