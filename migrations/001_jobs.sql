CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type                TEXT NOT NULL,
    payload             JSONB NOT NULL,
    idempotency_key     TEXT UNIQUE NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending', 'leased', 'done', 'dead')),
    attempts            INT NOT NULL DEFAULT 0,
    leased_by           TEXT,
    leased_until        TIMESTAMPTZ,
    run_after           TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Stamped by the reaper when it requeues an expired-but-recoverable
    -- lease; cleared by claim_batch() when the job is next claimed. Lets
    -- claim_batch() compute lease-recovery time in SQL (immune to any
    -- host/DB clock drift) for the lease_recovery_seconds histogram.
    lease_recovered_at  TIMESTAMPTZ
);

-- claim_batch()'s hot path: pending jobs whose run_after has arrived.
CREATE INDEX IF NOT EXISTS idx_jobs_claimable ON jobs (status, run_after) WHERE status = 'pending';

-- reap_expired_leases()'s hot path: leased jobs whose lease has expired.
CREATE INDEX IF NOT EXISTS idx_jobs_leased_expiry ON jobs (status, leased_until) WHERE status = 'leased';

-- idempotency_key is the webhook delivery ID (X-GitHub-Delivery): each
-- distinct GitHub delivery is its own job row, not a per-PR accumulator —
-- a "synchronize" event on the same PR is a new delivery, hence a new job.
