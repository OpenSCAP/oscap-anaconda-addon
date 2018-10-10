import pytest

import mock

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
    return mock.Mock()


def test_evaluation_existing_part_must_exist_rules(
        rule_data, ksdata_mock, storage_mock):
    rules = [
        "part /tmp",
        "part /",
    ]
    for rule in rules:
        rule_data.new_rule(rule)

    tmp_part_mock = mock.Mock()
    tmp_part_mock.format.options = "defaults"
    root_part_mock = mock.Mock()
    root_part_mock.format.options = "defaults"

    storage_mock.mountpoints = {
        "/tmp": tmp_part_mock,
        "/": root_part_mock,
    }

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # partitions exist --> no errors, warnings or additional info
    assert not messages

    # no additional mount options specified
    assert tmp_part_mock.format.options == "defaults"
    assert root_part_mock.format.options == "defaults"


def test_evaluation_nonexisting_part_must_exist(rule_data, ksdata_mock, storage_mock):
    rules = [
        "part /tmp",
        "part /",
    ]
    for rule in rules:
        rule_data.new_rule(rule)

    tmp_part_mock = mock.Mock()
    tmp_part_mock.format.options = "defaults"

    storage_mock.mountpoints = {
        "/tmp": tmp_part_mock,
    }

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # / mount point missing --> one error
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_FATAL

    # error has to mention the mount point
    assert "/" in messages[0].text


def get_partition_mocks(mount_options):
    tmp_part_mock = mock.Mock()
    tmp_part_mock.format.options = mount_options["/tmp"]
    root_part_mock = mock.Mock()
    root_part_mock.format.options = mount_options["/"]

    partition_mocks = {
        "/tmp": tmp_part_mock,
        "/": root_part_mock,
    }
    return partition_mocks


def set_mount_options_of_actual_mount_points(
        storage_mock, mount_options, actual_mountpoints):
    storage_mock.mountpoints = {}
    for mountpoint, value in mount_options.items():
        if mountpoint in actual_mountpoints:
            storage_mock.mountpoints[mountpoint] = value


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

    mount_options = get_partition_mocks(mount_options)

    set_mount_options_of_actual_mount_points(storage_mock, mount_options, actual_mountpoints)

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
    assert storage_mock.mountpoints["/tmp"].format.options == "defaults,nodev"
    assert storage_mock.mountpoints["/"].format.options == "defaults,noauto"


def test_evaluation_add_mount_options(rule_data, ksdata_mock, storage_mock):
    evaluation_add_mount_options(rule_data, ksdata_mock, storage_mock, 1)


def test_evaluation_add_mount_options_no_duplicates(rule_data, ksdata_mock, storage_mock):
    evaluation_add_mount_options(rule_data, ksdata_mock, storage_mock, 2)


def test_evaluation_add_mount_options_report_only(rule_data, ksdata_mock, storage_mock):
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
    assert storage_mock.mountpoints["/tmp"].format.options == "defaults"
    assert storage_mock.mountpoints["/"].format.options == "defaults"


def test_evaluation_add_mount_option_prefix(rule_data, ksdata_mock, storage_mock):
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
    assert storage_mock.mountpoints["/tmp"].format.options == "defaults,nodevice,nodev"


def test_evaluation_add_mount_options_nonexisting_part(rule_data, ksdata_mock, storage_mock):
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


def test_evaluation_passwd_minlen_no_passwd(rule_data, ksdata_mock, storage_mock):
    evaluation_passwd_minlen_no_passwd(rule_data, ksdata_mock, storage_mock, 8, (10, 11))
    evaluation_passwd_minlen_no_passwd(rule_data, ksdata_mock, storage_mock, 10, (8, 11))
    evaluation_passwd_minlen_no_passwd(rule_data, ksdata_mock, storage_mock, 11, (8, 10))


def evaluation_passwd_minlen_no_passwd(
        rule_data, ksdata_mock, storage_mock, min_password_length, check_against=tuple()):
    rule_data.new_rule("passwd --minlen={0}".format(min_password_length))

    ksdata_mock.rootpw.password = ""
    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # minimal password length required --> one warning
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_WARNING

    # warning has to mention the length
    assert str(min_password_length) in messages[0].text

    for not_wanted in check_against:
        assert str(not_wanted) not in messages[0].text


class passwordTestData(object):
    def __init__(self, rule_data, ksdata_mock, storage_mock):
        self.password = None
        self.isCrypted = False

        self.rule_data = rule_data
        self.ksdata_mock = ksdata_mock
        self.storage_mock = storage_mock

    def set_rule(self, rule_string):
        self.rule_data.new_rule(rule_string)

    def get_messages(self, report_only=False):
        self.ksdata_mock.rootpw.password = self.password
        self.ksdata_mock.rootpw.isCrypted = self.isCrypted
        return self.rule_data.eval_rules(
            self.ksdata_mock, self.storage_mock, report_only=report_only)


@pytest.fixture()
def password_data(rule_data, ksdata_mock, storage_mock):
    return passwordTestData(rule_data, ksdata_mock, storage_mock)


def test_evaluation_passwd_minlen_short_passwd(password_data):
    password_data.set_rule("passwd --minlen=8")
    password_data.password = "aaaa"

    messages = password_data.get_messages()

    # minimal password length greater than actual length --> one warning
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_FATAL

    # warning has to mention the length
    assert "8" in messages[0].text

    # warning should mention that something is wrong with the old password
    assert "is" in messages[0].text

    # doing changes --> password should not be cleared
    assert password_data.ksdata_mock.rootpw.password == "aaaa"


def test_evaluation_passwd_minlen_short_passwd_report_only(password_data):
    password_data.set_rule("passwd --minlen=8")
    password_data.password = "aaaa"

    messages = password_data.get_messages(report_only=True)

    # minimal password length greater than actual length --> one warning
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_FATAL

    # warning has to mention the length
    assert "8" in messages[0].text

    # report only --> password shouldn't be cleared
    assert password_data.ksdata_mock.rootpw.password == "aaaa"


def test_evaluation_passwd_minlen_crypted_passwd(password_data):
    password_data.set_rule("passwd --minlen=8")

    password_data.password = "aaaa"
    password_data.isCrypted = True

    messages = password_data.get_messages()

    # minimal password length greater than actual length --> one warning
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_WARNING

    # warning has to mention that the password cannot be checked
    assert "cannot check" in messages[0].text


def test_evaluation_passwd_minlen_good_passwd(password_data):
    password_data.set_rule("passwd --minlen=8")

    password_data.password = "aaaaaaaaaaaaaaaaa"

    messages = password_data.get_messages()

    # minimal password length less than actual length --> no warning
    assert not messages


def test_evaluation_passwd_minlen_report_only_not_ignored(password_data):
    password_data.set_rule("passwd --minlen=8")

    password_data.password = "aaaaaaaaaaaaaaaaa"

    messages = password_data.get_messages()

    # Mock pw_policy returned by anaconda.pwpolicy.get_policy()
    pw_policy_mock = mock.Mock()
    pw_policy_mock.minlen = 6
    pw_policy_mock.strict = False
    password_data.ksdata_mock.anaconda.pwpolicy.get_policy.return_value = pw_policy_mock

    # call eval_rules with report_only=False
    # should set password minimal length to 8
    messages = password_data.get_messages()

    # Password Policy changed --> no warnings
    assert not messages
    assert password_data.rule_data._passwd_rules._orig_minlen == 6
    assert not password_data.rule_data._passwd_rules._orig_strict
    assert pw_policy_mock.minlen == 8
    assert pw_policy_mock.strict
    assert password_data.rule_data._passwd_rules._minlen == 8

    # call of eval_rules with report_only=True
    # should not change anything
    messages = password_data.get_messages(report_only=True)
    # Password Policy stayed the same --> no warnings
    assert not messages

    assert password_data.rule_data._passwd_rules._orig_minlen == 6
    assert not password_data.rule_data._passwd_rules._orig_strict
    assert pw_policy_mock.minlen == 8
    assert pw_policy_mock.strict
    assert password_data.rule_data._passwd_rules._minlen == 8


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


def test_evaluation_package_rules(rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("package --add=firewalld --remove=telnet --add=iptables --add=vim")

    ksdata_mock.packages.packageList = ["vim"]
    ksdata_mock.packages.excludedList = []

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
    assert set(ksdata_mock.packages.packageList) == {"firewalld", "iptables", "vim"}
    assert set(ksdata_mock.packages.excludedList) == {"telnet"}


def test_evaluation_package_rules_report_only(rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("package --add=firewalld --remove=telnet --add=iptables")

    ksdata_mock.packages.packageList = []
    ksdata_mock.packages.excludedList = []

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
    assert not ksdata_mock.packages.packageList
    assert not ksdata_mock.packages.excludedList


def test_evaluation_bootloader_passwd_not_set(rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("bootloader --passwd")

    storage_mock.bootloader.password = None

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # bootloader password not set --> one warning
    assert len(messages) == 1
    assert messages[0].type == common.MESSAGE_TYPE_WARNING


def test_evaluation_bootloader_passwd_set(rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("bootloader --passwd")

    storage_mock.bootloader.password = "aaaaa"

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # bootloader password set --> no warnings
    assert messages == []


def test_evaluation_various_rules(rule_data, ksdata_mock, storage_mock):
    for rule in ["part /tmp", "part /", "passwd --minlen=14",
                 "package --add=firewalld", ]:
        rule_data.new_rule(rule)

    storage_mock.mountpoints = dict()
    ksdata_mock.packages.packageList = []
    ksdata_mock.packages.excludedList = []

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # four rules, all fail --> four messages
    assert len(messages) == 4


def test_revert_mount_options_nonexistent(rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("part /tmp --mountoptions=nodev")
    storage_mock.mountpoints = dict()

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # mount point doesn't exist -> one message, nothing done
    assert len(messages) == 1
    assert storage_mock.mountpoints == dict()

    # mount point doesn't exist -> shouldn't do anything
    rule_data.revert_changes(ksdata_mock, storage_mock)
    assert storage_mock.mountpoints == dict()


def test_revert_mount_options(rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("part /tmp --mountoptions=nodev")
    storage_mock.mountpoints = dict()
    storage_mock.mountpoints["/tmp"] = mock.Mock()
    storage_mock.mountpoints["/tmp"].format.options = "defaults"

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # mount option added --> one message
    assert len(messages) == 1

    # "nodev" option should be added
    assert storage_mock.mountpoints["/tmp"].format.options, "defaults == nodev"

    rule_data.revert_changes(ksdata_mock, storage_mock)

    # should be reverted to the original value
    assert storage_mock.mountpoints["/tmp"].format.options == "defaults"

    # another cycle of the same #
    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # mount option added --> one message
    assert len(messages) == 1

    # "nodev" option should be added
    assert storage_mock.mountpoints["/tmp"].format.options, "defaults == nodev"

    rule_data.revert_changes(ksdata_mock, storage_mock)

    # should be reverted to the original value
    assert storage_mock.mountpoints["/tmp"].format.options == "defaults"


def test_revert_password_policy_changes(rule_data, ksdata_mock, storage_mock):
    # FIXME: Add password policy changes to this test. It only checks
    # password length right now outside of policy changes.
    rule_data.new_rule("passwd --minlen=8")

    ksdata_mock.rootpw.password = "aaaa"
    ksdata_mock.rootpw.isCrypted = False
    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # password error --> one message
    assert len(messages) == 1
    assert ksdata_mock.rootpw.password == "aaaa"
    assert ksdata_mock.rootpw.seen

    rule_data.revert_changes(ksdata_mock, storage_mock)

    # with long enough password this time #
    ksdata_mock.rootpw.password = "aaaaaaaaaaaaa"

    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # long enough password
    # entered --> no message
    assert messages == []


def test_revert_package_rules(rule_data, ksdata_mock, storage_mock):
    rule_data.new_rule("package --add=firewalld --remove=telnet --add=iptables --add=vim")

    ksdata_mock.packages.packageList = ["vim"]
    ksdata_mock.packages.excludedList = []

    # run twice --> nothing should be different in the second run
    messages = rule_data.eval_rules(ksdata_mock, storage_mock)
    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # one info message for each added/removed package
    assert len(messages) == 3

    rule_data.revert_changes(ksdata_mock, storage_mock)

    # (only) added and excluded packages should have been removed from the
    # list
    assert ksdata_mock.packages.packageList == ["vim"]
    assert ksdata_mock.packages.excludedList == []

    # now do the same again #
    messages = rule_data.eval_rules(ksdata_mock, storage_mock)

    # one info message for each added/removed package
    assert len(messages) == 3

    rule_data.revert_changes(ksdata_mock, storage_mock)

    # (only) added and excluded packages should have been removed from the
    # list
    assert ksdata_mock.packages.packageList == ["vim"]
    assert ksdata_mock.packages.excludedList == []
