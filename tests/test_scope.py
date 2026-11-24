import pytest

from panoptes.scope import AuthorizationError, OutOfScopeError, Scope


def test_authorization_required():
    scope = Scope(allow=["example.com"], authorized=False)
    with pytest.raises(AuthorizationError):
        scope.require_authorization()


def test_authorization_requires_allowlist():
    scope = Scope(allow=[], authorized=True)
    with pytest.raises(AuthorizationError):
        scope.require_authorization()


def test_authorized_with_allow_ok():
    Scope(allow=["example.com"], authorized=True).require_authorization()


def test_host_allowed_wildcard():
    scope = Scope(allow=["*.example.com"], authorized=True)
    assert scope.host_allowed("api.example.com")
    assert not scope.host_allowed("example.com")  # wildcard needs a label
    assert not scope.host_allowed("evil.com")


def test_deny_beats_allow():
    scope = Scope(allow=["*.example.com"], deny=["admin.example.com"])
    assert not scope.host_allowed("admin.example.com")
    assert scope.host_allowed("www.example.com")


def test_check_url_rejects_out_of_scope():
    scope = Scope(allow=["example.com"], authorized=True)
    with pytest.raises(OutOfScopeError):
        scope.check_url("https://evil.com/")


def test_check_url_rejects_non_http():
    scope = Scope(allow=["example.com"], authorized=True)
    with pytest.raises(OutOfScopeError):
        scope.check_url("ftp://example.com/")


def test_private_host_blocked_by_default():
    scope = Scope(allow=["localhost"], authorized=True)
    with pytest.raises(OutOfScopeError):
        scope.check_url("http://127.0.0.1/")


def test_private_host_allowed_when_opted_in():
    scope = Scope(allow=["127.0.0.1"], authorized=True, allow_private=True)
    target = scope.check_url("http://127.0.0.1:8080/x")
    assert target.host == "127.0.0.1"
    assert target.port == 8080


def test_from_target_url():
    scope = Scope.from_target_url("https://shop.example.com/cart", authorized=True)
    assert scope.allow == ["shop.example.com"]
