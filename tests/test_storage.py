import os
import tempfile
import json

from safehaven import storage


def test_save_and_load_vault_with_key_roundtrip(tmp_path, monkeypatch):
    # create temporary vault path
    tmpfile = tmp_path / 'vault.json'
    monkeypatch.setattr(storage, 'VAULT_PATH', str(tmpfile))
    entries = [{'service':'s','username':'u','password':'p'}]
    # derive a key
    from safehaven.crypto import derive_key
    key, salt = derive_key('masterpw')
    # save using key
    storage.save_vault_with_key(entries, key, salt)
    loaded = storage.load_vault_with_key(key)
    assert isinstance(loaded, list)
    assert loaded[0]['service'] == 's'
