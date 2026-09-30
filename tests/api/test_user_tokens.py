"""The user-to-server token: stored server-side, never anywhere else.

Phase 2 needs one to list a visitor's OWN repositories — an installation
token cannot, being scoped to the installation rather than to the person
looking at the page. So sign-in obtains one and keeps it.

This is the first credential this application stores, which makes the
negative assertions the important ones: it must reach no cookie, no response
body, no header, no log line and no API response. A token in any of those is
a token in a browser profile, a proxy log, or a screenshot.
"""

from __future__ import annotations

import pytest

from codeguard.api import user_tokens

USER_ID = "183667058"
LOGIN = "ashrithaumd"
TOKEN = "ghu_aTestUserToServerTokenValue"
OTHER_TOKEN = "ghu_aReplacementTokenValue"


async def test_a_token_is_stored_and_read_back(pool):
    await user_tokens.store(pool, user_id=USER_ID, login=LOGIN, access_token=TOKEN)

    assert await user_tokens.get(pool, USER_ID) == TOKEN


async def test_signing_in_again_replaces_the_token(pool):
    """One live credential per person. Accumulating rows would mean a history
    of old tokens sitting there to be leaked."""
    await user_tokens.store(pool, user_id=USER_ID, login=LOGIN, access_token=TOKEN)
    await user_tokens.store(pool, user_id=USER_ID, login=LOGIN, access_token=OTHER_TOKEN)

    assert await user_tokens.get(pool, USER_ID) == OTHER_TOKEN
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) AS n FROM github_user_tokens WHERE user_id = %s", (USER_ID,))
        assert (await cur.fetchone())["n"] == 1


async def test_a_renamed_login_keeps_the_same_row(pool):
    """Keyed on the immutable numeric id, so a rename updates the row rather
    than creating a second one — and a released login re-registered by
    somebody else cannot collide with it."""
    await user_tokens.store(pool, user_id=USER_ID, login=LOGIN, access_token=TOKEN)
    await user_tokens.store(pool, user_id=USER_ID, login="renamed-account",
                            access_token=TOKEN)

    async with pool.connection() as conn:
        cur = await conn.execute("SELECT login FROM github_user_tokens WHERE user_id = %s",
                                 (USER_ID,))
        assert (await cur.fetchone())["login"] == "renamed-account"


async def test_an_unknown_user_has_no_token(pool):
    assert await user_tokens.get(pool, "999999999") is None
    assert await user_tokens.get(pool, "") is None
    assert await user_tokens.get(pool, None) is None


async def test_storing_without_an_id_is_refused(pool):
    """A row keyed on an empty id would be a shared credential for everyone
    whose id we failed to read."""
    with pytest.raises(ValueError):
        await user_tokens.store(pool, user_id="", login=LOGIN, access_token=TOKEN)
    with pytest.raises(ValueError):
        await user_tokens.store(pool, user_id=USER_ID, login=LOGIN, access_token="")
