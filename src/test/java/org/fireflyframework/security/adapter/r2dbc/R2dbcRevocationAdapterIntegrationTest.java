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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.test.StepVerifier;

import java.time.Instant;

/**
 * Real end-to-end integration test of the R2DBC revocation adapter against a live PostgreSQL
 * database provisioned by Testcontainers (Docker). Verifies persistence, the active/expired
 * distinction, idempotent upsert, and the not-revoked default. Named {@code *Test} so it runs
 * under Surefire (the module does not bind Failsafe).
 */
@Testcontainers
@SpringBootTest(classes = R2dbcRevocationAdapterIntegrationTest.TestApp.class)
class R2dbcRevocationAdapterIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s",
                POSTGRES.getHost(), POSTGRES.getFirstMappedPort(), POSTGRES.getDatabaseName()));
        registry.add("spring.r2dbc.username", POSTGRES::getUsername);
        registry.add("spring.r2dbc.password", POSTGRES::getPassword);
        registry.add("spring.sql.init.mode", () -> "always");
    }

    @Autowired
    RevocationPort revocationPort;

    @Test
    void revokedTokenIsReportedRevoked() {
        revocationPort.revoke("token-1", Instant.now().plusSeconds(300)).block();
        StepVerifier.create(revocationPort.isRevoked("token-1")).expectNext(true).verifyComplete();
    }

    @Test
    void unknownTokenIsNotRevoked() {
        StepVerifier.create(revocationPort.isRevoked("never-seen")).expectNext(false).verifyComplete();
    }

    @Test
    void expiredRevocationEntryNoLongerCounts() {
        revocationPort.revoke("token-expired", Instant.now().minusSeconds(60)).block();
        StepVerifier.create(revocationPort.isRevoked("token-expired")).expectNext(false).verifyComplete();
    }

    @Test
    void revokeIsIdempotentUpsert() {
        revocationPort.revoke("token-2", Instant.now().plusSeconds(120)).block();
        revocationPort.revoke("token-2", Instant.now().plusSeconds(600)).block();
        StepVerifier.create(revocationPort.isRevoked("token-2")).expectNext(true).verifyComplete();
    }

    @SpringBootApplication
    static class TestApp {
        @Bean
        RevocationPort revocationPort(DatabaseClient databaseClient) {
            return new R2dbcRevocationAdapter(databaseClient);
        }
    }
}
