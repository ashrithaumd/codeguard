-- Repo visibility, recorded per review so the dashboard can decide who
-- may see a row without asking GitHub at render time.
--
-- Recorded rather than looked up, for the same reason 006 stores the
-- RESOLVED gate/fix thresholds instead of re-reading .codeguard.yml: a
-- row has to stay interpretable on its own. A repo that was public when
-- reviewed and is private today should not retroactively expose its old
-- reviews, and — more importantly — a repo that has since been deleted
-- or had the App uninstalled would make a render-time lookup fail, and
-- a failing visibility lookup is not a safe default to guess at.
--
-- DEFAULT TRUE is deliberate and is the whole point of the column's
-- direction. Rows written before this migration have unknown visibility,
-- and the only safe assumption about unknown visibility is "private".
-- The cost of getting that wrong is a public repo's dashboard page
-- requiring a login; the cost of defaulting the other way is publishing
-- a private repo's findings, file paths and source fragments to anyone
-- with the URL. Backfill known-public repos explicitly if that matters.
--
-- NOT NULL with a default, so the ALTER is a metadata-only change on
-- Postgres 11+ and does not rewrite the table.
ALTER TABLE reviews
    ADD COLUMN IF NOT EXISTS private BOOLEAN NOT NULL DEFAULT TRUE;

-- The dashboard's index lists public reviews to anonymous visitors, so
-- "recent, public" is its hot path and the 006 created_at index alone
-- would make it scan private rows it must then discard.
CREATE INDEX IF NOT EXISTS reviews_public_created_idx
    ON reviews (created_at DESC) WHERE NOT private;
