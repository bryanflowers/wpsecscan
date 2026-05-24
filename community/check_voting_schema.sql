-- Round-64 #130 — "request a check" community-voting schema (PostgreSQL).
-- Backs a /community/check-requests page where users vote on which
-- new checks to prioritise.

CREATE TABLE IF NOT EXISTS check_requests (
    id              BIGSERIAL PRIMARY KEY,
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    submitter_email TEXT NOT NULL,        -- masked in public views
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    category        TEXT NOT NULL,         -- 'plugin', 'core', 'integration', 'reporter'
    motivation      TEXT,                  -- "why is this important"
    status          TEXT NOT NULL DEFAULT 'open',   -- open / planned / in-progress / done / rejected
    target_release  TEXT,                  -- e.g. "v2.3.0"
    closed_at       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS check_request_votes (
    id              BIGSERIAL PRIMARY KEY,
    request_id      BIGINT NOT NULL REFERENCES check_requests(id) ON DELETE CASCADE,
    voter_hash      CHAR(64) NOT NULL,     -- sha256 of voter's anonymous UUID
    vote_value      SMALLINT NOT NULL CHECK (vote_value IN (-1, 0, 1)),
    voted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(request_id, voter_hash)
);

CREATE INDEX ix_check_requests_status ON check_requests(status);
CREATE INDEX ix_check_request_votes_request ON check_request_votes(request_id);

-- View for the public dashboard (no PII)
CREATE OR REPLACE VIEW check_requests_public AS
SELECT
    cr.id,
    cr.submitted_at,
    cr.title,
    cr.description,
    cr.category,
    cr.status,
    cr.target_release,
    COALESCE(SUM(crv.vote_value), 0) AS net_score,
    COUNT(crv.id) AS vote_count
FROM check_requests cr
LEFT JOIN check_request_votes crv ON crv.request_id = cr.id
GROUP BY cr.id
ORDER BY net_score DESC;
