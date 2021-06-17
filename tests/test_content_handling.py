import os
import glob

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


def test_identify_files():
    filenames = glob.glob(TESTING_FILES_PATH + "/*")
    identified = ch.identify_files(filenames)
    assert identified[DS_FILEPATH] == ch.CONTENT_TYPES["DATASTREAM"]
    assert identified[
        os.path.join(TESTING_FILES_PATH, "scap-mycheck-oval.xml")] == ch.CONTENT_TYPES["OVAL"]
    assert identified[
        os.path.join(TESTING_FILES_PATH, "tailoring.xml")] == ch.CONTENT_TYPES["TAILORING"]
    assert identified[
        os.path.join(TESTING_FILES_PATH, "testing_xccdf.xml")] == ch.CONTENT_TYPES["XCCDF_CHECKLIST"]
    assert identified[
        os.path.join(TESTING_FILES_PATH, "cpe-dict.xml")] == ch.CONTENT_TYPES["CPE_DICT"]
