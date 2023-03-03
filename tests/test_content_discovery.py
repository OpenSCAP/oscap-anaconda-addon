import os

import pytest

import org_fedora_oscap.content_discovery as tested_module
from org_fedora_oscap import content_handling


@pytest.fixture
def labelled_files():
    return {
        "dir/datastream": "D",
        "dir/datastream2": "D",
        "dir/dir/datastream3": "D",
        "dir/dir/datastream3": "D",
        "dir/XCCDF": "X",
        "XCCDF2": "X",
        "cpe": "C",
        "t1": "T",
        "dir3/t2": "T",
    }


def test_reduce(labelled_files):
    bringer = tested_module.ContentBringer()

    d_count = 0
    x_count = 0
    for l in labelled_files.values():
        if l == "D":
            d_count += 1
        elif l == "X":
            x_count += 1

    reduced = bringer.reduce_files(labelled_files, "dir/datastream", ["D"])
    assert len(reduced) == len(labelled_files) - d_count + 1
    assert "dir/datastream" in reduced

    reduced = bringer.reduce_files(labelled_files, "dir/datastream", ["D", "X"])
    assert len(reduced) == len(labelled_files) - d_count - x_count + 1
    assert "dir/datastream" in reduced

    reduced = bringer.reduce_files(labelled_files, "dir/XCCDF", ["D", "X"])
    assert len(reduced) == len(labelled_files) - d_count - x_count + 1
    assert "dir/XCCDF" in reduced

    with pytest.raises(content_handling.ContentHandlingError, match="dir/datastream4"):
        bringer.reduce_files(labelled_files, "dir/datastream4", ["D"])

    reduced = bringer.reduce_files(labelled_files, "cpe", ["C"])
    assert reduced == labelled_files


def test_path_presence_detection():
    list_of_paths = ["file1", os.path.abspath("file2"), os.path.abspath("dir///file3")]

    list_of_paths_in_list = [
        "file1", os.path.abspath("file1"), "./file1",
        "file2", "dir/..//file2",
        "dir/../dir/file3", "dir/file3",
    ]
    list_of_paths_not_in_list = [
        "../file1", "file3"
    ]

    for path in list_of_paths_in_list:
        assert tested_module.path_is_present_among_paths(path, list_of_paths)

    for path in list_of_paths_not_in_list:
        assert not tested_module.path_is_present_among_paths(path, list_of_paths)
