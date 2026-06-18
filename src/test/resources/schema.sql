CREATE TABLE IF NOT EXISTS security_revoked_token (
    token_id   VARCHAR(512) PRIMARY KEY,
    expires_at TIMESTAMPTZ
);
