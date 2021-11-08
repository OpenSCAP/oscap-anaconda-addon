from org_fedora_oscap.scap_content_handler import SCAPContentHandler
from org_fedora_oscap.scap_content_handler import SCAPContentHandlerError
from org_fedora_oscap.scap_content_handler import ProfileInfo
import os
import pytest

TESTING_FILES_PATH = os.path.join(
    os.path.dirname(__file__), os.path.pardir, "testing_files")
DS_FILEPATH = os.path.join(TESTING_FILES_PATH, "testing_ds.xml")
XCCDF_FILEPATH = os.path.join(TESTING_FILES_PATH, "xccdf.xml")
TAILORING_FILEPATH = os.path.join(TESTING_FILES_PATH, "tailoring.xml")
OVAL_FILEPATH = os.path.join(TESTING_FILES_PATH, "scap-mycheck-oval.xml")

DS_IDS = "scap_org.open-scap_datastream_tst"
CHK_FIRST_ID = "scap_org.open-scap_cref_first-xccdf.xml"
CHK_SECOND_ID = "scap_org.open-scap_cref_second-xccdf.xml"


def test_init_invalid_file_path():
    with pytest.raises(FileNotFoundError) as excinfo:
        SCAPContentHandler("blbl")
    assert "No such file or directory: 'blbl'" in str(excinfo.value)


def test_init_sds():
    ch = SCAPContentHandler(DS_FILEPATH)
    assert ch.scap_type == "SCAP_SOURCE_DATA_STREAM"


def test_init_xccdf():
    ch = SCAPContentHandler(XCCDF_FILEPATH)
    assert ch.scap_type == "XCCDF"


def test_init_tailoring_of_sds():
    ch = SCAPContentHandler(TAILORING_FILEPATH)
    assert ch.scap_type == "TAILORING"


def test_init_tailoring_of_xccdf():
    ch = SCAPContentHandler(TAILORING_FILEPATH)
    assert ch.scap_type == "TAILORING"


def test_init_unsupported_scap_content_type():
    # the class SCAPContentHandler shouldn't support OVAL files
    with pytest.raises(SCAPContentHandlerError) as excinfo:
        SCAPContentHandler(OVAL_FILEPATH)
    assert "Unsupported SCAP content type" in str(excinfo.value)


def test_xccdf():
    ch = SCAPContentHandler(XCCDF_FILEPATH)

    checklists = ch.get_data_streams_checklists()
    assert checklists is None

    profiles = ch.get_profiles()
    assert len(profiles) == 2
    pinfo1 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile",
        title="My testing profile",
        description="A profile for testing purposes.")
    assert pinfo1 in profiles
    pinfo2 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile2",
        title="My testing profile2",
        description="Another profile for testing purposes.")
    assert pinfo2 in profiles

def test_xccdf_1_1():
    file_path = os.path.join(TESTING_FILES_PATH, "xccdf-1.1.xml")
    ch = SCAPContentHandler(file_path)

    checklists = ch.get_data_streams_checklists()
    assert checklists is None

    profiles = ch.get_profiles()
    assert len(profiles) == 2
    pinfo1 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile",
        title="My testing profile",
        description="A profile for testing purposes.")
    assert pinfo1 in profiles
    pinfo2 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile2",
        title="My testing profile2",
        description="Another profile for testing purposes.")
    assert pinfo2 in profiles


def test_xccdf_get_profiles_fails():
    ch = SCAPContentHandler(XCCDF_FILEPATH)
    with pytest.raises(SCAPContentHandlerError) as excinfo:
        ch.select_checklist("", "")
        profiles = ch.get_profiles()
    assert "For XCCDF documents, the data_stream_id and " \
        "checklist_id must be both None." in str(excinfo.value)


def test_sds():
    ch = SCAPContentHandler(DS_FILEPATH)
    checklists = ch.get_data_streams_checklists()
    assert checklists == {DS_IDS: [CHK_FIRST_ID, CHK_SECOND_ID]}

    ch.select_checklist(DS_IDS, CHK_FIRST_ID)
    profiles = ch.get_profiles()
    assert len(profiles) == 2
    pinfo1 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile",
        title="My testing profile",
        description="A profile for testing purposes.")
    assert pinfo1 in profiles
    pinfo2 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile2",
        title="My testing profile2",
        description="Another profile for testing purposes.")
    assert pinfo2 in profiles

    ch.select_checklist(DS_IDS, CHK_SECOND_ID)
    profiles2 = ch.get_profiles()
    assert len(profiles2) == 1
    pinfo3 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile3",
        title="My testing profile3",
        description="Yet another profile for testing purposes.")


def test_sds_get_profiles_fails():
    ch = SCAPContentHandler(DS_FILEPATH)

    with pytest.raises(SCAPContentHandlerError) as excinfo:
        profiles = ch.get_profiles()
    assert "For SCAP source data streams, data_stream_id and " \
        "checklist_id must be both different than None" in str(excinfo.value)

    with pytest.raises(SCAPContentHandlerError) as excinfo:
        ch.select_checklist(DS_IDS, checklist_id=None)
        profiles = ch.get_profiles()
    assert "For SCAP source data streams, data_stream_id and " \
        "checklist_id must be both different than None" in str(excinfo.value)

    with pytest.raises(SCAPContentHandlerError) as excinfo:
        wrong_cref = "scap_org.open-scap_cref_seventh-xccdf.xml"
        ch.select_checklist(DS_IDS, wrong_cref)
        profiles = ch.get_profiles()
    assert f"Can't find ds:component-ref with id='{wrong_cref}' in " \
        f"ds:datastream with id='{DS_IDS}'" in str(excinfo.value)


def test_tailoring():
    ch = SCAPContentHandler(DS_FILEPATH, TAILORING_FILEPATH)
    checklists = ch.get_data_streams_checklists()
    assert checklists == {DS_IDS: [CHK_FIRST_ID, CHK_SECOND_ID]}
    ch.select_checklist(DS_IDS, CHK_FIRST_ID)
    profiles = ch.get_profiles()
    assert len(profiles) == 4
    pinfo1 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile_tailored",
        title="My testing profile tailored",
        description="")
    assert pinfo1 in profiles
    pinfo2 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile2_tailored",
        title="My testing profile2 tailored",
        description="")
    assert pinfo2 in profiles
    # it should also include the profiles of the original benchmark
    pinfo3 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile",
        title="My testing profile",
        description="A profile for testing purposes.")
    assert pinfo3 in profiles
    pinfo4 = ProfileInfo(
        id="xccdf_com.example_profile_my_profile2",
        title="My testing profile2",
        description="Another profile for testing purposes.")
    assert pinfo4 in profiles


def test_default_profile():
    xccdf_filepath = os.path.join(TESTING_FILES_PATH, "testing_xccdf.xml")
    ch = SCAPContentHandler(xccdf_filepath)
    checklists = ch.get_data_streams_checklists()
    assert checklists is None
    profiles = ch.get_profiles()
    assert len(profiles) == 1
    pinfo1 = ProfileInfo(
        id="default",
        title="Default",
        description="The implicit XCCDF profile. Usually, the default profile "
        "contains no rules.")
    assert pinfo1 in profiles
