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
import logging
import tempfile
import pytest
from unittest.mock import Mock

from pyanaconda.modules.common.errors.installation import NonCriticalInstallationError

from org_fedora_oscap.service import installation
from org_fedora_oscap.structures import PolicyData

# FIXME: Extend the tests to test all paths of the installation tasks.


@pytest.fixture()
def file_path():
    with tempfile.NamedTemporaryFile() as f:
        yield f.name


@pytest.fixture()
def content_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture()
def tailoring_path():
    with tempfile.NamedTemporaryFile() as f:
        yield f.name


@pytest.fixture()
def sysroot_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture()
def rule_evaluator(monkeypatch):
    mock = Mock(return_value=[])
    monkeypatch.setattr("org_fedora_oscap.rule_handling.RuleData.eval_rules", mock)
    return mock


@pytest.fixture()
def mock_payload(monkeypatch):
    proxy = Mock()
    monkeypatch.setattr("org_fedora_oscap.common.get_payload_proxy", proxy)
    return proxy


def test_fetch_content_task(caplog, file_path, content_path):
    data = PolicyData()
    task = installation.PrepareValidContent(
        policy_data=data,
        file_path=file_path,
        content_path=content_path,
    )

    assert task.name == "Fetch the content, and optionally perform check or archive extraction"

    with pytest.raises(NonCriticalInstallationError, match="Couldn't find a valid datastream"):
        task.run()


def test_evaluate_rules_task(rule_evaluator, content_path, tailoring_path, mock_payload):
    data = PolicyData()
    task = installation.EvaluateRulesTask(
        policy_data=data,
        content_path=content_path,
        tailoring_path=tailoring_path
    )

    assert task.name == "Evaluate the rules"
    task.run()

    rule_evaluator.assert_called_once()


def test_install_content_task(sysroot_path, file_path, content_path, tailoring_path):
    data = PolicyData()
    data.content_type = "scap-security-guide"

    task = installation.InstallContentTask(
        sysroot=sysroot_path,
        policy_data=data,
        file_path=file_path,
        content_path=content_path,
        tailoring_path=tailoring_path,
        target_directory="target_dir"
    )

    assert task.name == "Install the content"
    task.run()


def test_remediate_system_task(sysroot_path, content_path, tailoring_path):
    data = PolicyData()
    task = installation.RemediateSystemTask(
        sysroot=sysroot_path,
        policy_data=data,
        target_content_path=content_path,
        target_tailoring_path=tailoring_path
    )

    assert task.name == "Remediate the system"
    task.run()
