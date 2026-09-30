-- User-to-server GitHub tokens, obtained during sign-in and kept
-- server-side. Phase 2 needs one to list a visitor's OWN repositories, which
-- an installation token cannot do: it is scoped to the installation, not to
-- the person looking at the page.
--
-- IDEMPOTENT, like every migration here: bootstrap_schema() applies every
-- migrations/*.sql on every api and worker startup.
--
-- ------------------------------------------------------------------
-- SECURITY, because this is the first table that holds a credential.
-- ------------------------------------------------------------------
-- A row here grants whatever the App's user-to-server scope grants, on
-- behalf of that person, until it expires. Consequences, stated plainly:
--
--   * IT IS STORED IN PLAINTEXT. Azure Database for PostgreSQL encrypts at
--     rest, so this is protected against someone walking off with a disk,
--     and NOT against anything that can read the database — a leaked
--     connection string, a SQL injection, or a database dump in a backup
--     bucket. Encrypting the column would mean a key to manage and a key to
--     leak instead; the honest position is that this table is as sensitive
--     as DATABASE_URL and is recorded as an accepted risk in SECURITY.md.
--   * IT NEVER LEAVES THE SERVER. No route returns it, no template renders
--     it, no log line prints it. tests/api/test_user_tokens.py asserts the
--     sign-in response contains it in no cookie, body or header.
--   * DELETED ON SIGN-OUT is deliberately NOT done. The token outlives the
--     session by design: a background job acting for that user (phase 2's
--     "audit my repo") must keep working after they close the tab. Sign-out
--     ends the SESSION; revoking the grant is done on GitHub.
--
-- Keyed on the numeric user id rather than the login, for the same reason
-- the operator allow-list is: a login can be renamed and re-registered by
-- somebody else, and a row keyed on one would then belong to the wrong
-- person. The login is stored alongside for diagnosis only.
CREATE TABLE IF NOT EXISTS github_user_tokens (
    user_id       TEXT PRIMARY KEY,
    login         TEXT        NOT NULL,
    access_token  TEXT        NOT NULL,
    -- GitHub App user-to-server tokens expire (8 hours by default) and may
    -- come with a refresh token when the App has expiry enabled. Both are
    -- recorded so phase 2 can decide whether to refresh or to re-prompt;
    -- nothing refreshes them today.
    expires_at    TIMESTAMPTZ,
    refresh_token TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Signing in again replaces the token rather than accumulating rows, so
-- there is exactly one live credential per person and no history of old
-- ones lying around to leak.
CREATE INDEX IF NOT EXISTS github_user_tokens_login_idx
    ON github_user_tokens (lower(login));
