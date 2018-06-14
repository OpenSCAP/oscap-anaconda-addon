import tempfile
import filecmp
import contextlib
import pathlib
import sys
import subprocess
import time

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


def test_file_retreival():
    filename_to_test = pathlib.Path(__file__)
    relative_filename_to_test = filename_to_test.relative_to(pathlib.Path.cwd())

    temp_file = tempfile.NamedTemporaryFile()
    temp_filename = temp_file.name

    with serve_directory_in_separate_process(PORT):
        data_fetch._curl_fetch(
            "http://localhost:{}/{}".format(PORT, relative_filename_to_test), temp_filename)

    assert filecmp.cmp(relative_filename_to_test, temp_filename)


def test_supported_url():
    assert data_fetch.can_fetch_from("http://example.com")
    assert data_fetch.can_fetch_from("https://example.com")


def test_unsupported_url():
    assert not data_fetch.can_fetch_from("aaaaa")
