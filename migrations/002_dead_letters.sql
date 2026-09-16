-- Terminal graveyard. A job row is DELETEd from `jobs` and moved here — by
-- nack() exhausting attempts, or by the reaper finding an expired lease
-- already at/over max attempts (a crash-looping worker that never got a
-- chance to call nack() itself). `id` is carried over from the original
-- jobs.id, not regenerated, so a dead letter is still traceable.
CREATE TABLE IF NOT EXISTS dead_letters (
    id               UUID PRIMARY KEY,
    type             TEXT NOT NULL,
    payload          JSONB NOT NULL,
    idempotency_key  TEXT NOT NULL,
    attempts         INT NOT NULL,
    failed_reason    TEXT,
    moved_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at       TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dead_letters_moved_at ON dead_letters (moved_at DESC);
