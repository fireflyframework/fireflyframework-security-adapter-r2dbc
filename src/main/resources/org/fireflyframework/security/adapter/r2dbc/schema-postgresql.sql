-- Firefly security R2DBC adapter — reference schema (PostgreSQL).
-- Apply via Flyway/Liquibase or spring.sql.init in the consuming application.

CREATE TABLE IF NOT EXISTS security_revoked_token (
    token_id   VARCHAR(512) PRIMARY KEY,
    expires_at TIMESTAMPTZ
);

-- Index to support scheduled pruning of expired revocations.
CREATE INDEX IF NOT EXISTS idx_security_revoked_token_expires_at
    ON security_revoked_token (expires_at);
