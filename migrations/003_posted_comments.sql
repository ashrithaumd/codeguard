-- Idempotency guard for the GitHub side effect itself — mirrors
-- Reliqueue's sent_emails pattern (UNIQUE + ON CONFLICT DO NOTHING), just
-- applied to our domain. The queue guarantees at-least-once *delivery*,
-- not at-most-once *side effect*: a worker that posts a comment and then
-- crashes before ack() causes a redelivery that would otherwise post the
-- same comment again. GitHub's comment API has no idempotency key of its
-- own to lean on; idempotency_key (the webhook delivery_id) is ours, so
-- we guard with it directly.
CREATE TABLE IF NOT EXISTS posted_comments (
    idempotency_key  TEXT PRIMARY KEY,
    job_id           UUID NOT NULL,
    posted_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
