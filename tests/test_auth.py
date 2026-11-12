from datetime import datetime, timedelta, timezone

import pytest

from ops_mcp.auth import ALL_SCOPES, AuthError, TokenStore


def test_create_then_verify_round_trip(store):
    token = store.create("triage-agent", ["read:logs", "read:metrics"])
    p = store.verify(token)
    assert p.name == "triage-agent" and p.scopes == {"read:logs", "read:metrics"}


def test_only_a_hash_is_stored(store, tmp_path):
    token = store.create("a", ["read:logs"])
    secret = token.split("_", 2)[2]
    path = tmp_path / "tokens.json"
    store.save(path)
    assert secret not in path.read_text()


def test_store_survives_save_and_load(store, tmp_path):
    token = store.create("a", ["read:logs"])
    store.save(tmp_path / "t.json")
    assert TokenStore.load(tmp_path / "t.json").verify(token).name == "a"


@pytest.mark.parametrize("bad", [None, "", "garbage", "opsm_", "opsm_abcd", "opsm_abcd_wrong", "Bearer x"])
def test_bad_tokens_get_the_same_error(store, bad):
    store.create("a", ["read:logs"])
    with pytest.raises(AuthError, match="invalid or expired token"):
        store.verify(bad)


def test_wrong_secret_for_real_id_is_indistinguishable_from_unknown_id(store):
    token = store.create("a", ["read:logs"])
    token_id = token.split("_")[1]
    with pytest.raises(AuthError) as wrong_secret:
        store.verify(f"opsm_{token_id}_nope")
    with pytest.raises(AuthError) as unknown_id:
        store.verify("opsm_ffffffff_nope")
    assert str(wrong_secret.value) == str(unknown_id.value)


def test_revoked_token_is_rejected(store):
    token = store.create("a", ["read:logs"])
    assert store.revoke(token.split("_")[1]) is True
    with pytest.raises(AuthError):
        store.verify(token)


def test_expired_token_is_rejected(store):
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    token = store.create("a", ["read:logs"], expires_at=past)
    with pytest.raises(AuthError):
        store.verify(token)


def test_unexpired_token_works(store):
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert store.verify(store.create("a", ["read:logs"], expires_at=future)).name == "a"


def test_unknown_scope_cannot_be_issued(store):
    with pytest.raises(ValueError, match="unknown scopes"):
        store.create("a", ["read:logs", "write:everything"])


def test_all_scopes_are_issuable(store):
    assert store.verify(store.create("root", list(ALL_SCOPES))).scopes == set(ALL_SCOPES)
