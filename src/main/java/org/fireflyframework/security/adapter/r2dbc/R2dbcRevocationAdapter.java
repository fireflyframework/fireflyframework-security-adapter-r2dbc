/*
 * Copyright 2024-2026 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fireflyframework.security.adapter.r2dbc;

import org.fireflyframework.security.spi.RevocationPort;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Relational-database {@link RevocationPort} backed by R2DBC. Persists a revocation list so that a
 * still-unexpired, validly-signed token can be rejected. Entries are self-expiring: an entry whose
 * {@code expires_at} has passed no longer counts as revoked (the token has expired anyway), letting
 * a scheduled cleanup prune the table without race conditions.
 *
 * <p>Expected schema (see {@code schema-postgresql.sql}):
 * <pre>{@code
 * CREATE TABLE security_revoked_token (token_id VARCHAR(512) PRIMARY KEY, expires_at TIMESTAMPTZ);
 * }</pre>
 */
public class R2dbcRevocationAdapter implements RevocationPort {

    private static final String UPSERT = """
            INSERT INTO security_revoked_token (token_id, expires_at) VALUES (:id, :exp)
            ON CONFLICT (token_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
            """;

    private static final String EXISTS_ACTIVE = """
            SELECT 1 FROM security_revoked_token
            WHERE token_id = :id AND (expires_at IS NULL OR expires_at > now())
            """;

    private final DatabaseClient databaseClient;

    public R2dbcRevocationAdapter(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<Void> revoke(String tokenId, Instant expiresAt) {
        DatabaseClient.GenericExecuteSpec spec = databaseClient.sql(UPSERT).bind("id", tokenId);
        spec = (expiresAt == null)
                ? spec.bindNull("exp", OffsetDateTime.class)
                : spec.bind("exp", expiresAt.atOffset(ZoneOffset.UTC));
        return spec.then();
    }

    @Override
    public Mono<Boolean> isRevoked(String tokenId) {
        return databaseClient.sql(EXISTS_ACTIVE)
                .bind("id", tokenId)
                .map((row, metadata) -> Boolean.TRUE)
                .one()
                .defaultIfEmpty(Boolean.FALSE);
    }
}
