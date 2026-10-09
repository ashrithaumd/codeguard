-- Audits requested by URL from the Repositories page, as distinct from the
-- Run audit button on an installed repository's row.
--
-- The difference is who may read the result (routes/dashboard.py,
-- _may_read_audit):
--
--   by_url = FALSE  repo access (through the App's installation) AND
--                   requester-or-operator -- unchanged
--   by_url = TRUE   the requester only, other operators included, and NO
--                   repo-access check: the repository need not have the App
--                   installed, and the access check goes through the
--                   installation, so it would refuse even the requester.
--
-- Every existing row is FALSE, so nothing already stored changes who can
-- read it. IDEMPOTENT, like every migration here.

ALTER TABLE audits ADD COLUMN IF NOT EXISTS by_url BOOLEAN NOT NULL DEFAULT FALSE;

-- "Your audits by URL", newest first, on the Repositories page.
CREATE INDEX IF NOT EXISTS audits_by_url_requester_idx
    ON audits (lower(requested_by), created_at DESC) WHERE by_url;
