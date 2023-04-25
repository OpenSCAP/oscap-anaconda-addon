import filecmp
import contextlib
import pathlib
import sys
import subprocess
import time

import pytest

from org_fedora_oscap import data_fetch


PORT = 8001


@contextlib.contextmanager
def serve_directory_in_separate_process(port):
    args = [sys.executable, "-m", "http.server", str(port)]
    proc = subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    # give the server some time to start
    time.sleep(0.4)
    yield
    proc.terminate()
    proc.wait()


def test_file_retreival(tmp_path):
    filename_to_test = pathlib.Path(__file__)
    relative_filename_to_test = filename_to_test.relative_to(pathlib.Path.cwd())
    temp_filename = tmp_path / "dest"

    with serve_directory_in_separate_process(PORT):
        data_fetch._curl_fetch(
            "http://localhost:{}/{}".format(PORT, relative_filename_to_test), temp_filename)

    assert filecmp.cmp(relative_filename_to_test, temp_filename)


def test_file_absent():
    relative_filename_to_test = "i_am_not_here.file"

    with serve_directory_in_separate_process(PORT):
        with pytest.raises(data_fetch.FetchError) as exc:
            data_fetch._curl_fetch(
                "http://localhost:{}/{}".format(PORT, relative_filename_to_test), "/dev/null")
            assert "error code 404" in str(exc)


def test_supported_url():
    assert data_fetch.can_fetch_from("http://example.com")
    assert data_fetch.can_fetch_from("https://example.com")


def test_unsupported_url():
    assert not data_fetch.can_fetch_from("aaaaa")


def test_fetch_local(tmp_path):
    source_path = pathlib.Path(__file__).absolute()
    dest_path = tmp_path / "dest"
    data_fetch.fetch_data("file://" + str(source_path), dest_path)
    with open(dest_path, "r") as copied_file:
        assert "This line is here and in the copied file as well" in copied_file.read()
