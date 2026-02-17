import base64
from safehaven.crypto import derive_key, legacy_sha256_key


def test_derive_key_length_and_type():
    key, salt = derive_key('testpassword')
    assert isinstance(key, (bytes,))
    assert isinstance(salt, (bytes,))
    assert len(base64.urlsafe_b64decode(key)) == 32


def test_legacy_key_matches_length():
    k = legacy_sha256_key('test')
    assert isinstance(k, (bytes,))
    assert len(base64.urlsafe_b64decode(k)) == 32
