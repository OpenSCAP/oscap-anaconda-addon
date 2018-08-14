import os

import pytest

from org_fedora_oscap import content_handling as ch


TESTING_FILES_PATH = os.path.join(
    os.path.dirname(__file__), os.path.pardir, "testing_files")
DS_FILEPATH = os.path.join(
    TESTING_FILES_PATH, "testing_ds.xml")

DS_IDS = "scap_org.open-scap_datastream_tst"
CHK_FIRST_ID = "scap_org.open-scap_cref_first-xccdf.xml"
CHK_SECOND_ID = "scap_org.open-scap_cref_second-xccdf.xml"

PROFILE1_ID = "xccdf_com.example_profile_my_profile"
PROFILE2_ID = "xccdf_com.example_profile_my_profile2"
PROFILE3_ID = "xccdf_com.example_profile_my_profile3"


@pytest.fixture()
def ds_handler():
    return ch.DataStreamHandler(DS_FILEPATH)


def test_init_invalid_file_path():
    with pytest.raises(ch.DataStreamHandlingError) as excinfo:
        ch.DataStreamHandler("testing_ds.xmlll")
    assert "Invalid file path" in str(excinfo.value)


def test_init_not_scap_content():
    with pytest.raises(ch.DataStreamHandlingError) as excinfo:
        ch.DataStreamHandler(os.path.join(TESTING_FILES_PATH, "testing_ks.cfg"))
    assert "not a valid SCAP content file" in str(excinfo.value)


def test_init_xccdf_content():
    with pytest.raises(ch.DataStreamHandlingError) as excinfo:
        ch.DataStreamHandler(os.path.join(TESTING_FILES_PATH, "xccdf.xml"))
    assert "not a data stream collection" in str(excinfo.value)


def test_get_data_streams(ds_handler):
    assert DS_IDS in ds_handler.get_data_streams()


def test_get_data_streams_checklists(ds_handler):
    expected_ids = {DS_IDS: [CHK_FIRST_ID, CHK_SECOND_ID]}

    ds_ids = ds_handler.get_data_streams_checklists()
    assert expected_ids == ds_ids


def test_get_checklists(ds_handler):
    expected_checklists = [CHK_FIRST_ID, CHK_SECOND_ID]

    chk_ids = ds_handler.get_checklists(DS_IDS)
    assert expected_checklists == chk_ids


def test_get_checklists_invalid(ds_handler):
    with pytest.raises(ch.DataStreamHandlingError) as excinfo:
        ds_handler.get_checklists("invalid.id")
        assert "Invalid data stream id given" in str(excinfo.value)


def test_get_profiles(ds_handler):
    profile_ids = ds_handler.get_profiles(DS_IDS, CHK_FIRST_ID)

    # When Benchmark doesn't contain Rules selected by default
    # the default Profile should not be present
    assert 2 == len(profile_ids)
    assert PROFILE1_ID == profile_ids[0].id
    assert PROFILE2_ID == profile_ids[1].id


def test_get_profiles_with_default(ds_handler):
    profile_ids = ds_handler.get_profiles(DS_IDS, CHK_SECOND_ID)

    # When Benchmark contains Rules selected by default
    # the default Profile should be present
    assert 2 == len(profile_ids)
    assert "default" == profile_ids[0].id
    assert PROFILE3_ID == profile_ids[1].id
