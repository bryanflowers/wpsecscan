-- Round-64 #123 — Opt-in community-shared scan DB schema (PostgreSQL).
-- Submitters consent via WPSECSCAN_PUBLIC_SHARE=1; only anonymised
-- summary stats are uploaded — never finding detail with URLs.

CREATE TABLE IF NOT EXISTS public_scans (
    id              BIGSERIAL PRIMARY KEY,
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Sha256 of (target_url + submitter_anon_id), never the URL itself
    target_hash     CHAR(64) NOT NULL,
    -- Sha256 of a UUID local to the submitter (rotated quarterly)
    submitter_hash  CHAR(64) NOT NULL,
    wpsecscan_version TEXT NOT NULL,
    summary_critical INTEGER NOT NULL DEFAULT 0,
    summary_high     INTEGER NOT NULL DEFAULT 0,
    summary_medium   INTEGER NOT NULL DEFAULT 0,
    summary_low      INTEGER NOT NULL DEFAULT 0,
    summary_info     INTEGER NOT NULL DEFAULT 0,
    grade           CHAR(2) NOT NULL,    -- A+/A/B/C/D/F
    -- Aggregate-only: list of check_ids that fired, no details
    check_ids_fired TEXT[] NOT NULL DEFAULT '{}',
    -- Optional: WP core version, hosted-platform fingerprint
    wp_version_major SMALLINT,
    wp_version_minor SMALLINT,
    hosting_platform TEXT,              -- e.g. "wp-engine", "kinsta", "self"
    country_iso2     CHAR(2)             -- from CDN geo only
);

CREATE INDEX ix_public_scans_submitted_at ON public_scans(submitted_at DESC);
CREATE INDEX ix_public_scans_grade ON public_scans(grade);
CREATE INDEX ix_public_scans_hosting_platform ON public_scans(hosting_platform);

CREATE TABLE IF NOT EXISTS check_fire_frequency (
    -- Rolled up nightly from public_scans for fast dashboard queries
    check_id        TEXT PRIMARY KEY,
    fire_count_30d  BIGINT NOT NULL DEFAULT 0,
    fire_count_90d  BIGINT NOT NULL DEFAULT 0,
    last_rollup_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Privacy notes:
--  - target_url is NEVER stored; only the hash
--  - submitter_uuid is rotated by the client every 90 days
--  - submitter can request deletion of all rows matching their hash
--    via /privacy/forget endpoint (TBD)
--  - country_iso2 is derived server-side from CDN geo; client never sends location
