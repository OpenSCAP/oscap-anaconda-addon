import pytest
import mock
from collections import defaultdict

from pyanaconda.core.constants import PAYLOAD_TYPE_DNF
from pyanaconda.core.constants import PASSWORD_POLICY_ROOT
from pyanaconda.modules.common.constants.objects import FIREWALL, DEVICE_TREE, BOOTLOADER
from pyanaconda.modules.common.constants.objects import USER_INTERFACE
from pyanaconda.modules.common.constants.services import NETWORK, STORAGE, USERS, BOSS, PAYLOADS
from pyanaconda.modules.common.structures.payload import PackagesConfigurationData
from pyanaconda.modules.common.structures.policy import PasswordPolicy

from org_fedora_oscap.common import KDUMP


try:
    from org_fedora_oscap import rule_handling, common
except ImportError as exc:
    pytestmark = pytest.mark.skip(
        "Unable to import modules, possibly due to bad version of Anaconda: {error}"
        .format(error=str(exc)))


@pytest.fixture()
def part_rules():
    rules = rule_handling.PartRules()
    rules.ensure_mount_point("/tmp")
    return rules


# simple tests, shouldn't raise exceptions
def test_part_rules_getitem(part_rules):
    part_rules["/tmp"]


def test_part_rules_setitem(part_rules):
    rule = rule_handling.PartRule("/var/log")
    part_rules["/var/log"] = rule


def test_part_rules_len(part_rules):
    assert len(part_rules) == 1


def test_part_rules_contains(part_rules):
    assert "/tmp" in part_rules


def test_part_rules_delitem(part_rules):
    del(part_rules["/tmp"])
    assert "/tmp" not in part_rules


@pytest.fixture()
def rule_data():
    return rule_handling.RuleData()


def test_rule_data_artificial(rule_data):
    rule_data.new_rule("  part /tmp --mountoptions=nodev,noauto")
    rule_data.new_rule("part /var/log  ")
    rule_data.new_rule(" passwd   --minlen=14 ")
    rule_data.new_rule("package --add=iptables")
    rule_data.new_rule(" package --add=firewalld --remove=telnet")
    rule_data.new_rule("package --remove=rlogin --remove=sshd")
    rule_data.new_rule("bootloader --passwd")

    # both partitions should appear in rule_data._part_rules
    assert "/tmp" in rule_data._part_rules
    assert "/var/log" in rule_data._part_rules

    # mount options should be parsed
    assert "nodev" in rule_data._part_rules["/tmp"]._mount_options
    assert "noauto" in rule_data._part_rules["/tmp"]._mount_options

    # no mount options for /var/log
    assert not rule_data._part_rules["/var/log"]._mount_options

    # minimal password length should be parsed and stored correctly
    assert rule_data._passwd_rules._minlen == 14

    # packages should be parsed correctly
    assert "iptables" in rule_data._package_rules._add_pkgs
    assert "firewalld" in rule_data._package_rules._add_pkgs
    assert "telnet" in rule_data._package_rules._remove_pkgs
    assert "rlogin" in rule_data._package_rules._remove_pkgs
    assert "sshd" in rule_data._package_rules._remove_pkgs

    # bootloader should require password
    assert rule_data._bootloader_rules._require_password


def test_rule_data_quoted_opt_values(rule_data):
    rule_data.new_rule('part /tmp --mountoptions="nodev,noauto"')

    assert "nodev" in rule_data._part_rules["/tmp"]._mount_options
    assert "noauto" in rule_data._part_rules["/tmp"]._mount_options
    assert '"' not in rule_data._part_rules["/tmp"]._mount_options


def test_rule_data_real_output(rule_data):
    output = """
    part /tmp

    part /tmp --mountoptions=nodev
    """
    for line in output.splitlines():
        rule_data.new_rule(line)

    assert "/tmp" in rule_data._part_rules
    assert "nodev" in rule_data._part_rules["/tmp"]._mount_options

    # should be stripped and merged
    assert str(rule_data._part_rules) == "part /tmp --mountoptions=nodev"


@pytest.fixture()
def ksdata_mock():
    return mock.Mock()


@pytest.fixture()
def storage_mock():
    return None


# monkeypatch is a predefined fixture that is used to perform per-test case changes in the test env.
# Here, it mocks the Anaconda interface on the module level. For more info, see:
# https://docs.pytest.org/en/latest/monkeypatch.html#monkeypatching-mocking-modules-and-environments
@pytest.fixture()
def proxy_getter(monkeypatch):
    proxies = defaultdict(mock.Mock)

    def mock_get(service_name, object_path, *args, **kwargs):
        initialize = not proxies
        proxy = proxies[(service_name, object_path)]

        if initialize:
            set_dbus_defaults()

        return proxy

    monkeypatch.setattr("pyanaconda.core.dbus.DBus.get_proxy", mock_get)
    return mock_get


def set_dbus_defaults():
    boss = BOSS.get_proxy()
    boss.GetModules.return_value = [
        KDUMP.service_name
    ]

    kdump = KDUMP.get_proxy()
    kdump.KdumpEnabled = True

    user_interface = BOSS.get_proxy(USER_INTERFACE)
    user_interface.PasswordPolicies = {}

    network = NETWORK.get_proxy()
    network.Connected.return_value = True

    firewall = NETWORK.get_proxy(FIREWALL)
    firewall.EnabledServices = []
    firewall.DisabledServices = []
    firewall.EnabledPorts = []
    firewall.Trusts = []

    device_tree = STORAGE.get_proxy(DEVICE_TREE)
    device_tree.GetDeviceMountOptions.return_value = "defaults"
    device_tree.GetMountPoints.return_value = {}

    bootloader = STORAGE.get_proxy(BOOTLOADER)
    bootloader.IsPasswordSet = False

    users = USERS.get_proxy()
    users.IsRootPasswordSet = True
    users.IsRootPasswordCrypted = False
    users.RootPassword = "anaconda"

    payloads = PAYLOADS.get_proxy()
    payloads.ActivePayload = "/fake/payload/1"

    dnf_payload = PAYLOADS.get_proxy("/fake/payload/1")
    dnf_payload.Type = PAYLOAD_TYPE_DNF

    packages_data = PackagesConfigurationData()
    dnf_payload.Packages = PackagesConfigurationData.to_structure(packages_data)


def test_evaluation_existing_part_must_exist_rules(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    rules = [
        "part /tmp",
        "part /",
    ]
    for rule in rules:
        rule_data.new_rule(rule)

    device_tree_mock = STORAGE.get_proxy(DEVICE_TREE)
    device_tree_mock.GetDeviceMountOptions.return_value = "defaults"
    device_tree_mock.GetMountPoints.return_value = {
        "/tmp": "/dev/sda1",
        "/": "/dev/sda2",
    }

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # partitions exist --> no errors, warnings or additional info
    assert not messages

    # no additional mount options specified
    device_tree_mock.SetDeviceMountOptions.assert_has_calls([
        mock.call("/dev/sda1", "defaults"),
        mock.call("/dev/sda2", "defaults"),
    ])


def test_evaluation_nonexisting_part_must_exist(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    rules = [
        "part /tmp",
        "part /",
    ]
    for rule in rules:
        rule_data.new_rule(rule)

    device_tree_mock = STORAGE.get_proxy(DEVICE_TREE)
    device_tree_mock.GetDeviceMountOptions.return_value = "defaults"
    device_tree_mock.GetMountPoints.return_value = {
        "/tmp": "/dev/sda1",
    }

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # / mount point missing --> one error
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_FATAL

    # error has to mention the mount point
    assert "/" in messages[0].text


def get_messages_for_partition_rules(
        rule_data, ksdata_mock, storage_mock,
        rules,
        messages_evaluation_count=1,
        actual_mountpoints=("/tmp", "/"),
        mount_options=None,
        report_only=False,
        ):

    assert len(rules) == 2, \
        "We need rules for temp partition and root."

    if mount_options is None:
        mount_options = {
            "/": "defaults",
            "/tmp": "defaults",
        }

    for rule in rules:
        rule_data.new_rule(rule)

    # Map mount points to device names.
    mount_points = {}

    if "/tmp" in actual_mountpoints:
        mount_points["/tmp"] = "/dev/sda1"

    if "/" in actual_mountpoints:
        mount_points["/"] = "/dev/sda2"

    # Map device names to mount options.
    mount_options = {
        mount_points[mount_point]: mount_options[mount_point]
        for mount_point in actual_mountpoints
    }

    # Mock the device tree proxy.
    def get_device_mount_options(device_name):
        return mount_options[device_name]

    def set_device_mount_options(device_name, options):
        mount_options[device_name] = options

    device_tree_mock = STORAGE.get_proxy(DEVICE_TREE)
    device_tree_mock.GetMountPoints.return_value = mount_points
    device_tree_mock.GetDeviceMountOptions.side_effect = get_device_mount_options
    device_tree_mock.SetDeviceMountOptions.side_effect = set_device_mount_options

    messages = []
    for _ in range(messages_evaluation_count):
        messages = rule_data.eval_rules(ksdata_mock, storage_mock, report_only)

    return messages


def evaluation_add_mount_options(
        rule_data, ksdata_mock, storage_mock,
        messages_evaluation_count):
    rules = [
        "part /tmp --mountoptions=defaults,nodev",
        "part / --mountoptions=noauto",
    ]

    messages = get_messages_for_partition_rules(
        rule_data, ksdata_mock, storage_mock,
        rules, messages_evaluation_count)

    # two mount options added --> two info messages
    assert len(messages) == 2
    assert all(message.type == common.MESSAGE_TYPE_INFO for message in messages)

    # newly added mount options should be mentioned in the messages
    # together with their mount points
    nodev_found = False
    noauto_found = False

    for message in messages:
        if "'nodev'" in message.text:
            assert "/tmp" in message.text
            nodev_found = True
        elif "'noauto'" in message.text:
            assert "/" in message.text
            noauto_found = True

    assert all([nodev_found, noauto_found])

    device_tree_mock = STORAGE.get_proxy(DEVICE_TREE)
    device_tree_mock.SetDeviceMountOptions.assert_has_calls([
        mock.call("/dev/sda1", "defaults,nodev"),
        mock.call("/dev/sda2", "defaults,noauto"),
    ])


def test_evaluation_add_mount_options(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    evaluation_add_mount_options(rule_data, ksdata_mock, storage_mock, 1)


def test_evaluation_add_mount_options_no_duplicates(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    evaluation_add_mount_options(rule_data, ksdata_mock, storage_mock, 2)


def test_evaluation_add_mount_options_report_only(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    rules = [
        "part /tmp --mountoptions=nodev",
        "part / --mountoptions=noauto",
    ]
    messages = get_messages_for_partition_rules(
        rule_data, ksdata_mock, storage_mock,
        rules, 1, report_only=True)

    # two mount options added --> two info messages
    assert len(messages) == 2
    assert messages[0].type == common.MESSAGE_TYPE_INFO
    assert messages[1].type == common.MESSAGE_TYPE_INFO

    # newly added mount options should be mentioned in the messages
    # together with their mount points
    nodev_found = False
    noauto_found = False

    for message in messages:
        if "'nodev'" in message.text:
            assert "/tmp" in message.text
            nodev_found = True
        elif "'noauto'" in message.text:
            assert "/" in message.text
            noauto_found = True

    assert all([nodev_found, noauto_found])

    # no changes should be made
    device_tree_mock = STORAGE.get_proxy(DEVICE_TREE)
    device_tree_mock.SetDeviceMountOptions.assert_not_called()


def test_evaluation_add_mount_option_prefix(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    rules = [
        "part /tmp --mountoptions=nodev",
        "part / --mountoptions=noauto",
    ]
    mount_options = {
        "/": "defaults",
        "/tmp": "defaults,nodevice",
    }
    messages = get_messages_for_partition_rules(
        rule_data, ksdata_mock, storage_mock,
        rules, mount_options=mount_options)

    # two mount options added (even though it is a prefix of another one)
    #   --> two info messages
    assert len(messages) == 2
    assert messages[0].type == common.MESSAGE_TYPE_INFO
    assert messages[1].type == common.MESSAGE_TYPE_INFO

    # the option should be added even though it is a prefix of another one
    device_tree_mock = STORAGE.get_proxy(DEVICE_TREE)
    device_tree_mock.SetDeviceMountOptions.assert_has_calls([
        mock.call("/dev/sda1", "defaults,nodevice,nodev"),
    ])


def test_evaluation_add_mount_options_nonexisting_part(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    rules = [
        "part /tmp --mountoptions=nodev",
        "part / --mountoptions=noauto",
    ]
    messages = get_messages_for_partition_rules(
        rule_data, ksdata_mock, storage_mock,
        rules, actual_mountpoints=["/"])

    # one mount option added, one mount point missing (mount options
    # cannot be added) --> one info, one error
    assert len(messages) == 2
    assert any(message.type == common.MESSAGE_TYPE_INFO for message in messages)
    assert any(message.type == common.MESSAGE_TYPE_FATAL for message in messages)

    # the info message should report mount options added to the existing
    # mount point, the error message shoud contain the missing mount point
    # and not the mount option
    for message in messages:
        if message.type == common.MESSAGE_TYPE_INFO:
            assert "/" in message.text
            assert "'noauto'" in message.text
        elif message.type == common.MESSAGE_TYPE_FATAL:
            assert "/tmp" in message.text
            assert "'nodev'" not in message.text


def test_evaluation_passwd_minlen_no_passwd(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    password_proxy_mock = USERS.get_proxy()
    password_proxy_mock.IsRootPasswordSet = False
    evaluation_passwd_minlen_no_passwd(rule_data, ksdata_mock, storage_mock, 8, (10, 11))
    evaluation_passwd_minlen_no_passwd(rule_data, ksdata_mock, storage_mock, 10, (8, 11))
    evaluation_passwd_minlen_no_passwd(rule_data, ksdata_mock, storage_mock, 11, (8, 10))


def evaluation_passwd_minlen_no_passwd(
        rule_data, ksdata_mock, storage_mock, min_password_length, check_against=tuple()):
    rule_data.new_rule("passwd --minlen={0}".format(min_password_length))

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # minimal password length required --> one warning
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_WARNING

    # warning has to mention the length
    assert str(min_password_length) in messages[0].text

    for not_wanted in check_against:
        assert str(not_wanted) not in messages[0].text


def test_evaluation_passwd_minlen_short_passwd(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    password_proxy_mock = USERS.get_proxy()
    password_proxy_mock.IsRootPasswordCrypted = False
    password_proxy_mock.RootPassword = "aaaa"

    rule_data.new_rule("passwd --minlen=8")

    messages = rule_data.eval_rules(ksdata_mock, storage_mock, report_only=False)

    # minimal password length greater than actual length --> one warning
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_FATAL

    # warning has to mention the length
    assert "8" in messages[0].text

    # warning should mention that something is wrong with the old password
    assert "is" in messages[0].text

    # doing changes --> password should not be cleared
    assert password_proxy_mock.RootPassword == "aaaa"


def test_evaluation_passwd_minlen_short_passwd_report_only(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    password_proxy_mock = USERS.get_proxy()
    password_proxy_mock.IsRootPasswordCrypted = False
    password_proxy_mock.RootPassword = "aaaa"

    rule_data.new_rule("passwd --minlen=8")

    messages = rule_data.eval_rules(ksdata_mock, storage_mock, report_only=True)

    # minimal password length greater than actual length --> one warning
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_FATAL

    # warning has to mention the length
    assert "8" in messages[0].text

    # warning should mention that something is wrong with the old password
    assert "is" in messages[0].text

    # doing changes --> password should not be cleared
    assert password_proxy_mock.RootPassword == "aaaa"


def test_evaluation_passwd_minlen_crypted_passwd(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    password_proxy_mock = USERS.get_proxy()
    password_proxy_mock.IsRootPasswordCrypted = True
    password_proxy_mock.RootPassword = "aaaa"

    rule_data.new_rule("passwd --minlen=8")

    messages = rule_data.eval_rules(ksdata_mock, storage_mock, report_only=False)

    # minimal password length greater than actual length --> one warning
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_WARNING

    # warning has to mention that the password cannot be checked
    assert "cannot check" in messages[0].text


def test_evaluation_passwd_minlen_good_passwd(proxy_getter, rule_data, ksdata_mock, storage_mock):
    password_proxy_mock = USERS.get_proxy()
    password_proxy_mock.IsRootPasswordCrypted = False
    password_proxy_mock.RootPassword = "aaaaaaaaaaaaaaaaa"

    rule_data.new_rule("passwd --minlen=8")

    messages = rule_data.eval_rules(ksdata_mock, storage_mock, report_only=False)

    # minimal password length less than actual length --> no warning
    assert not messages


def test_evaluation_passwd_minlen_report_only_not_ignored(
        proxy_getter, rule_data, ksdata_mock, storage_mock):
    password_proxy_mock = USERS.get_proxy()
    password_proxy_mock.IsRootPasswordCrypted = False
    password_proxy_mock.RootPassword = "aaaaaaaaaaaaaaaaa"

    rule_data.new_rule("passwd --minlen=8")

    messages = rule_data.eval_rules(ksdata_mock, storage_mock, report_only=False)

    # call eval_rules with report_only=False
    # should set password minimal length to 8
    messages = rule_data.eval_rules(ksdata_mock, storage_mock, report_only=False)

    # Password Policy changed --> no warnings
    assert not messages
    assert rule_data._passwd_rules._orig_minlen == 6
    assert not rule_data._passwd_rules._orig_strict
    assert rule_data._passwd_rules._minlen == 8

    policy = PasswordPolicy.from_defaults(PASSWORD_POLICY_ROOT)
    policy.min_length = 8
    policy.is_strict = True

    policies = {PASSWORD_POLICY_ROOT: policy}

    ui_mock = BOSS.get_proxy(USER_INTERFACE)
    ui_mock.SetPasswordPolicies.assert_called_with(
        PasswordPolicy.to_structure_dict(policies)
    )
    ui_mock.SetPasswordPolicies.reset_mock()

    # call of eval_rules with report_only=True
    # should not change anything
    messages = rule_data.eval_rules(ksdata_mock, storage_mock, report_only=True)
    # Password Policy stayed the same --> no warnings
    assert not messages

    assert rule_data._passwd_rules._orig_minlen == 6
    assert not rule_data._passwd_rules._orig_strict
    assert rule_data._passwd_rules._minlen == 8

    ui_mock.SetPasswordPolicies.assert_not_called()


def _occurences_not_seen_in_strings(seeked, strings):
    found = set(seeked)
    for string in strings:
        for might_have_seen in seeked:
            if might_have_seen in string:
                found.add(string)
                break
    return set(seeked).difference(found)


def _quoted_keywords_not_seen_in_messages(keywords, messages):
    return _occurences_not_seen_in_strings(
        {"'{}'".format(kw) for kw in keywords},
        [m.text for m in messages],
    )


def test_evaluation_package_rules(proxy_getter, rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("package --add=firewalld --remove=telnet --add=iptables --add=vim")

    packages_data = PackagesConfigurationData()
    packages_data.packages = ["vim"]

    dnf_payload_mock = PAYLOADS.get_proxy("/fake/payload/1")
    dnf_payload_mock.Packages = PackagesConfigurationData.to_structure(packages_data)

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # one info message for each (really) added/removed package
    assert len(messages) == 3
    assert all(message.type == common.MESSAGE_TYPE_INFO for message in messages)

    # all packages should appear in the messages
    not_seen = _quoted_keywords_not_seen_in_messages(
        {"firewalld", "telnet", "iptables"},
        messages,
    )
    assert not not_seen

    packages_data = PackagesConfigurationData()
    packages_data.packages = ["vim", "firewalld", "iptables"]
    packages_data.excluded_packages = ["telnet"]

    dnf_payload_mock.SetPackages.assert_called_once_with(
        PackagesConfigurationData.to_structure(packages_data)
    )


def test_evaluation_package_rules_report_only(proxy_getter, rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("package --add=firewalld --remove=telnet --add=iptables")

    messages = rule_data.eval_rules(ksdata_mock, storage_mock, report_only=True)

    # one info message for each added/removed package
    assert len(messages) == 3
    assert all(message.type == common.MESSAGE_TYPE_INFO for message in messages)

    not_seen = _quoted_keywords_not_seen_in_messages(
        {"firewalld", "telnet", "iptables"},
        messages,
    )

    assert not not_seen

    # report_only --> no packages should be added or excluded
    dnf_payload_mock = PAYLOADS.get_proxy("/fake/payload/1")
    dnf_payload_mock.SetPackages.assert_not_called()


def test_evaluation_bootloader_passwd_not_set(proxy_getter, rule_data, ksdata_mock, storage_mock):
    bootloader_proxy_mock = STORAGE.get_proxy(BOOTLOADER)
    bootloader_proxy_mock.IsPasswordSet = False

    rule_data.new_rule("bootloader --passwd")

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # bootloader password not set --> one warning
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_WARNING


def test_evaluation_bootloader_passwd_set(proxy_getter, rule_data, ksdata_mock, storage_mock):
    bootloader_proxy_mock = STORAGE.get_proxy(BOOTLOADER)
    bootloader_proxy_mock.IsPasswordSet = True

    rule_data.new_rule("bootloader --passwd")

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # bootloader password set --> no warnings
    assert messages == []


def test_evaluation_various_rules(proxy_getter, rule_data, ksdata_mock, storage_mock):
    for rule in ["part /tmp", "part /", "passwd --minlen=14",
                 "package --add=firewalld", ]:
        rule_data.new_rule(rule)

    ksdata_mock.packages.packageList = []
    ksdata_mock.packages.excludedList = []

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # four rules, all fail --> four messages
    assert len(messages) == 4


def test_revert_mount_options_nonexistent(proxy_getter, rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("part /tmp --mountoptions=nodev")

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # mount point doesn't exist -> one message, nothing done
    assert len(messages) == 1

    device_tree_mock = STORAGE.get_proxy(DEVICE_TREE)
    device_tree_mock.SetDeviceMountOptions.assert_not_called()

    # mount point doesn't exist -> shouldn't do anything
    rule_data.revert_changes(ksdata_mock, storage_mock)

    device_tree_mock.SetDeviceMountOptions.assert_not_called()


def test_revert_mount_options(proxy_getter, rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("part /tmp --mountoptions=nodev")

    device_tree_mock = STORAGE.get_proxy(DEVICE_TREE)
    device_tree_mock.GetMountPoints.return_value = {
        "/tmp": "/dev/sda1",
    }

    def set_mount_options(device_name, mount_options):
        assert device_name == "/dev/sda1"
        device_tree_mock.GetDeviceMountOptions.return_value = mount_options

    device_tree_mock.SetDeviceMountOptions.side_effect = set_mount_options
    device_tree_mock.GetDeviceMountOptions.return_value = "defaults"

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # mount option added --> one message
    assert len(messages) == 1

    # "nodev" option should be added
    device_tree_mock.SetDeviceMountOptions.assert_called_once_with(
        "/dev/sda1", "defaults,nodev"
    )

    rule_data.revert_changes(ksdata_mock, storage_mock)

    # should be reverted to the original value
    device_tree_mock.SetDeviceMountOptions.assert_called_with(
        "/dev/sda1", "defaults"
    )

    # another cycle of the same #
    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # mount option added --> one message
    assert len(messages) == 1

    # "nodev" option should be added
    device_tree_mock.SetDeviceMountOptions.assert_called_with(
        "/dev/sda1", "defaults,nodev"
    )

    rule_data.revert_changes(ksdata_mock, storage_mock)

    # should be reverted to the original value
    device_tree_mock.SetDeviceMountOptions.assert_called_with(
        "/dev/sda1", "defaults"
    )


def test_revert_password_policy_changes(proxy_getter, rule_data, ksdata_mock, storage_mock):
    password_proxy_mock = USERS.get_proxy()
    password_proxy_mock.IsRootPasswordCrypted = False
    password_proxy_mock.RootPassword = "aaaa"

    # FIXME: Add password policy changes to this test. It only checks
    # password length right now outside of policy changes.
    rule_data.new_rule("passwd --minlen=8")

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # password error --> one message
    assert len(messages) == 1

    rule_data.revert_changes(ksdata_mock, storage_mock)

    # with long enough password this time #
    password_proxy_mock.RootPassword = "aaaaaaaaaaaaa"

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # long enough password
    # entered --> no message
    assert messages == []


def test_revert_package_rules(proxy_getter, rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("package --add=firewalld --remove=telnet --add=iptables --add=vim")

    packages_data = PackagesConfigurationData()
    packages_data.packages = ["vim"]

    dnf_payload_mock = PAYLOADS.get_proxy("/fake/payload/1")
    dnf_payload_mock.Packages = PackagesConfigurationData.to_structure(packages_data)

    def set_packages(structure):
        dnf_payload_mock.Packages = structure

    dnf_payload_mock.SetPackages.side_effect = set_packages

    # run twice --> nothing should be different in the second run
    messages = rule_data.eval_rules(ksdata_mock, storage_mock)
    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # one info message for each added/removed package
    assert len(messages) == 3

    rule_data.revert_changes(ksdata_mock, storage_mock)

    # (only) added and excluded packages should have been removed from the
    # list
    dnf_payload_mock.SetPackages.assert_called_with(
        PackagesConfigurationData.to_structure(packages_data)
    )

    # now do the same again #
    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # one info message for each added/removed package
    assert len(messages) == 3

    rule_data.revert_changes(ksdata_mock, storage_mock)

    # (only) added and excluded packages should have been removed from the
    # list
    dnf_payload_mock.SetPackages.assert_called_with(
        PackagesConfigurationData.to_structure(packages_data)
    )
