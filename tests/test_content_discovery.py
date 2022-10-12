import pytest

import org_fedora_oscap.content_discovery as tested_module


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
    bringer = tested_module.ContentBringer(None)

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

    with pytest.raises(RuntimeError, match="dir/datastream4"):
        bringer.reduce_files(labelled_files, "dir/datastream4", ["D"])

    reduced = bringer.reduce_files(labelled_files, "cpe", ["C"])
    assert reduced == labelled_files
