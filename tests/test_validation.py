from recon.validation import validate_domain


def test_valid_domain():
    assert validate_domain("example.com") is True


def test_invalid_domain():
    assert validate_domain("hello") is False


def test_url_is_invalid():
    assert validate_domain("https://example.com") is False


def test_domain_with_path_is_invalid():
    assert validate_domain("example.com/test") is False


def test_empty_domain_is_invalid():
    assert validate_domain("") is False