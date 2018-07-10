from org_fedora_oscap import data_fetch


def test_supported_url():
    assert data_fetch.can_fetch_from("http://example.com")
    assert data_fetch.can_fetch_from("https://example.com")


def test_unsupported_url():
    assert not data_fetch.can_fetch_from("aaaaa")
