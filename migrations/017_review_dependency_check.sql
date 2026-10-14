-- "Dependency CVE check unavailable" on the review page: TRUE when OSV could
-- not be reached for this push, so an empty dependency result is never read
-- as a clean one (tools/osv_runner.check_dependency_updates_status).
--
-- Every existing row is FALSE: reviews recorded before this column cannot
-- say, and showing the note on them would claim a failure nobody saw.
-- IDEMPOTENT, like every migration here.

ALTER TABLE reviews ADD COLUMN IF NOT EXISTS dependency_check_unavailable BOOLEAN NOT NULL DEFAULT FALSE;
