-- Phase 7: per-content-hash agent result cache. Keyed by the exact
-- content an agent reviewed — a whole file's content hash for the
-- file-scoped agents (security, ai_aware, both driven by a
-- deterministic tool's already file-level findings), or one hunk's own
-- content_hash (codeguard/diff/parse.py's build_hunks, ~30-line
-- expanded context) for the hunk-scoped agents (quality, test).
-- content_hash alone doesn't encode which file it came from, so path
-- is part of the key too — otherwise two different files sharing a
-- byte-identical block (e.g. common boilerplate) would incorrectly
-- share a cache entry across files.
--
-- On a `synchronize` webhook, worker/main.py looks up every (path,
-- content_hash, agent) this PR is about to review; a hit means no LLM
-- call at all for that content — see codeguard/pipeline/hunk_cache.py.
-- findings_json/dismissed_json store Finding/DismissedFinding lists via
-- Pydantic's own JSON serialization, so a hit reconstructs the agent's
-- exact prior output with no re-derivation.
CREATE TABLE IF NOT EXISTS hunk_findings (
    owner               TEXT NOT NULL,
    repo                TEXT NOT NULL,
    path                TEXT NOT NULL,
    content_hash        TEXT NOT NULL,
    agent               TEXT NOT NULL,
    findings_json       JSONB NOT NULL,
    dismissed_json      JSONB NOT NULL DEFAULT '[]'::jsonb,
    tokens_in           INT NOT NULL DEFAULT 0,
    tokens_out          INT NOT NULL DEFAULT 0,
    estimated_cost_usd  DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner, repo, path, content_hash, agent)
);
