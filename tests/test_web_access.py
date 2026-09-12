import pytest
from cvevidence.web_access import principal, release_label

def account(**changes):
    return {"is_logged_in": True, "email_verified": True, "email": "a@example.com",
            "sub": "google-user-one", **changes}

@pytest.mark.parametrize("changes", [
    {"is_logged_in": False}, {"email_verified": False},
    {"email_verified": "true"}, {"sub": ""}, {"email": "outsider@example.com"},
])
def test_rejects_untrusted_or_uninvited_identity(changes):
    with pytest.raises(ValueError):
        principal(account(**changes), ["a@example.com"])

def test_subject_scopes_storage_without_embedding_email():
    first = principal(account(), ["A@EXAMPLE.COM"])
    assert len(first) == 64 and "@" not in first
    assert first == principal(account(email="A@example.com"), ["a@example.com"])
    assert first != principal(account(sub="google-user-two"), ["a@example.com"])

def test_release_label_rejects_arbitrary_content():
    assert release_label("b239cb0") == "b239cb0"
    assert release_label("<script>") == "unversioned"
