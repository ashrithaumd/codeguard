-- "New repository" notices on the Repositories page.
--
-- One row per repository GitHub has told us was added to the App's
-- installation: installation_repositories (added), which an install on
-- "All repositories" sends when a repository is created, forked into the
-- account or transferred in, and installation (created) for the initial
-- list. Removed from the installation -> the row is deleted, so a
-- repository added again later is announced again.
--
-- Operators only. Dismissal is shared, not per viewer: there is one
-- installation and the notice is about it.
--
-- IDEMPOTENT, like every migration here.

CREATE TABLE IF NOT EXISTS repo_notices (
    owner         TEXT NOT NULL,
    repo          TEXT NOT NULL,
    private       BOOLEAN NOT NULL DEFAULT TRUE,
    added_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    dismissed_at  TIMESTAMPTZ,
    dismissed_by  TEXT
);

-- Case-insensitive, like repo_settings. A redelivery of the same event is
-- ON CONFLICT DO NOTHING, so it neither duplicates a notice nor revives a
-- dismissed one.
CREATE UNIQUE INDEX IF NOT EXISTS repo_notices_owner_repo
    ON repo_notices (lower(owner), lower(repo));
