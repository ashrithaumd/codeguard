-- Audits gain a 'rejected' terminal state, and in-flight fairness per
-- requester as well as per repository.
--
-- IDEMPOTENT, like every migration here: bootstrap_schema() applies every
-- migrations/*.sql on EVERY api and worker startup, so each statement has
-- to be safe to run against a database that already has it. That is why
-- the CHECK is dropped by name before being recreated rather than altered.
--
-- requested_by is NOT added here. It already exists -- migration 009 line
-- 27, TEXT NOT NULL, populated by audits.request_audit() since the column
-- was introduced. Adding it again would be a no-op at best.

-- ---------------------------------------------------------------------
-- 'rejected': refused before doing the work, as distinct from 'failed'.
-- ---------------------------------------------------------------------
-- The difference is whose problem it is, and it is worth a separate state
-- because the UI says something different for each:
--
--   rejected  we declined to audit this. Too large, not public, not
--             Python, demo budget exhausted. Nothing went wrong; the
--             answer is no. Usually not worth retrying unchanged.
--   failed    we tried and could not finish. Clone died, worker was
--             dead-lettered, a scanner or model call broke. Retrying is
--             reasonable.
--
-- Collapsing them would force one message to cover "this repository is
-- too large" and "something broke, try again", which are opposite
-- instructions to the person reading the page.
--
-- 'timed_out' is here too, in ONE migration rather than a later widening.
-- bootstrap_schema() re-runs every migration on every startup, and
-- ADD CONSTRAINT VALIDATES EXISTING ROWS -- so a 010 that forbade
-- 'timed_out' followed by an 011 that allowed it would fail permanently
-- the moment a single timed-out audit existed: 010 would run first, find
-- the row, and refuse. Found by the constraint violating on a database
-- that already had one. A CHECK recreated on every startup has to list
-- every value the schema will ever hold, so the list lives in one place.
--
-- WHY timed_out IS ITS OWN STATUS rather than 'failed' with a message:
-- distinguishing outcomes by the wording of user-facing copy breaks
-- silently the first time someone rewords it, and it breaks in the
-- direction of telling people to retry something that cannot succeed. A
-- timeout is also genuinely neither of the others -- 'failed' says
-- something broke, 'rejected' says we declined before starting, and a
-- timeout means we started, did real work, spent real money, and ran out
-- of time. The page's advice differs for each.
ALTER TABLE audits DROP CONSTRAINT IF EXISTS audits_status_check;
ALTER TABLE audits
    ADD CONSTRAINT audits_status_check
    CHECK (status IN ('queued', 'running', 'done', 'failed', 'rejected', 'timed_out'));

-- ---------------------------------------------------------------------
-- One in-flight audit per REQUESTER, alongside the existing per-repo one.
-- ---------------------------------------------------------------------
-- Both, because they stop different things and neither implies the other:
--
--   per repo (009)  two people must not each pay to audit the same
--                   repository at the same time
--   per requester   one person must not queue fifty audits and spend the
--                   operator's whole budget in a minute
--
-- Partial on the in-flight states only, exactly as 009's is, so this
-- constrains CONCURRENCY and never history: a requester can run any
-- number of audits over time, just not at once.
--
-- NOTE FOR THE ROUTE: these two constraints need DIFFERENT error handling.
-- Hitting the per-repo index means someone else's audit is in flight, and
-- the caller must NOT be redirected to it -- a visitor audit is visible
-- only to its requester, so handing over its id would leak it. Hitting
-- the per-requester index means the caller's OWN audit is in flight, and
-- redirecting to it is exactly right. request_audit() distinguishes them
-- by constraint name.
CREATE UNIQUE INDEX IF NOT EXISTS audits_one_in_flight_per_user
    ON audits (requested_by) WHERE status IN ('queued', 'running');

-- "Your recent audits, newest first" -- the visitor landing page's main
-- query, and the only one that filters on requested_by.
CREATE INDEX IF NOT EXISTS audits_requested_by_created_idx
    ON audits (requested_by, created_at DESC);
