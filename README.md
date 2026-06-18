# Firefly Framework - Security R2DBC Adapter

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21%2B-orange.svg)](https://openjdk.org)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-green.svg)](https://spring.io/projects/spring-boot)

> R2DBC/relational-database adapter for the Firefly security platform. Implements the `RevocationPort` driven SPI on top of any R2DBC-supported relational database (tested against PostgreSQL), so token revocation works with **no external cache server required**. This is the data-repository alternative to the Redis-backed adapter.

---

## Table of Contents

- [Overview](#overview)
- [Where it sits](#where-it-sits-in-the-hexagonal-security-platform)
- [What it provides](#what-it-provides)
- [Schema](#schema)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Dependencies](#dependencies)
- [Testing](#testing)
- [Documentation](#documentation)
- [License](#license)

## Overview

The Firefly security platform is a **product-agnostic, hexagonal** security stack built on Spring Security 6 and Spring WebFlux. Its core never imports a vendor SDK; outbound capabilities are expressed as driven ports in `fireflyframework-security-spi` and satisfied by interchangeable adapters.

This module is one such adapter. It implements **`RevocationPort`** — the seam that lets the platform reject a still-unexpired, validly-signed token (a logout, a forced session kill, a compromised credential) — using a relational table reached over R2DBC. It is the **data-repository alternative** to `fireflyframework-security-adapter-redis`: when an application already runs a relational database and does not want to operate a separate cache server, it can pick this adapter and get the same fail-closed revocation semantics from durable storage.

The adapter holds no domain concepts. It stores only an opaque `token_id` (for a JWT, typically the `jti`) and an optional expiry. Nothing here is tied to any particular product, tenant model, or business role.

## Where it sits in the hexagonal security platform

```
api  ->  spi  ->  core  ->  webflux  ->  resource-server  ->  adapters
```

| Layer | Module | Role |
| --- | --- | --- |
| `api` | `fireflyframework-security-api` | Driving ports + neutral domain (`SecurityPrincipal`, decisions, …). |
| `spi` | `fireflyframework-security-spi` | Driven ports, including **`RevocationPort`**. |
| `core` | `fireflyframework-security-core` | Vendor-neutral engine; depends on ports, never on adapters. |
| `webflux` | `fireflyframework-security-webflux` | Reactive binding of the core to Spring WebFlux. |
| `resource-server` | `fireflyframework-security-resource-server` | Bearer validation, revocation check, secure-by-default headers/CORS/CSRF. |
| `adapters` | **`fireflyframework-security-adapter-r2dbc`** (this module), `-adapter-redis`, … | Concrete `RevocationPort` (and sibling-port) implementations. |

The resource server consults `RevocationPort.isRevoked(...)` while validating an inbound bearer token and **fails closed**: a revoked (or unverifiable) token is rejected. This adapter depends only on `fireflyframework-security-api` and `fireflyframework-security-spi` — it never reaches back into the core or webflux layers, preserving the hexagonal dependency direction.

## What it provides

### `R2dbcRevocationAdapter` (implements `org.fireflyframework.security.spi.RevocationPort`)

A reactive, R2DBC-backed revocation list. Constructed with a single Spring `DatabaseClient`:

```java
public R2dbcRevocationAdapter(DatabaseClient databaseClient)
```

It implements the two `RevocationPort` operations:

| Method | Behavior |
| --- | --- |
| `Mono<Void> revoke(String tokenId, Instant expiresAt)` | **Idempotent upsert** into `security_revoked_token` (`INSERT ... ON CONFLICT (token_id) DO UPDATE`). `expiresAt` may be `null` (bound as a SQL `NULL`), meaning the entry never self-expires; otherwise it is stored as a `TIMESTAMPTZ` at UTC. |
| `Mono<Boolean> isRevoked(String tokenId)` | Returns `true` only for an entry that exists **and is still active** (`expires_at IS NULL OR expires_at > now()`). An unknown token returns `false` via `defaultIfEmpty(false)`. |

**Self-expiring entries.** Because `isRevoked` ignores rows whose `expires_at` has passed, an expired revocation no longer counts as revoked — the token has expired anyway. This decouples correctness from cleanup: a scheduled job can prune the table at leisure (the `idx_security_revoked_token_expires_at` index supports this) without any race against active checks.

## Schema

The adapter targets a single table. A reference PostgreSQL DDL ships at
`src/main/resources/org/fireflyframework/security/adapter/r2dbc/schema-postgresql.sql`:

```sql
CREATE TABLE IF NOT EXISTS security_revoked_token (
    token_id   VARCHAR(512) PRIMARY KEY,
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_security_revoked_token_expires_at
    ON security_revoked_token (expires_at);
```

Apply it the way your application manages schema — Flyway, Liquibase, or `spring.sql.init.*`. The adapter does not create or migrate the table itself.

## Requirements

- Java 21+
- Spring Boot 3.x with a reactive (R2DBC) data stack
- A relational database with an R2DBC driver. The reference schema and the integration test target **PostgreSQL** (`r2dbc-postgresql`); the SQL used (`ON CONFLICT`, `TIMESTAMPTZ`, `now()`) is PostgreSQL-flavored.

## Installation

The version is managed by the Firefly parent/BOM, so you can omit it:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-adapter-r2dbc</artifactId>
</dependency>
```

If you are not inheriting the Firefly parent, pin the version explicitly:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-adapter-r2dbc</artifactId>
    <version>26.06.01</version>
</dependency>
```

Choose **this adapter or** `fireflyframework-security-adapter-redis` for `RevocationPort` — not both.

## Usage

Provide the adapter as the application's `RevocationPort` bean, wired from a Spring R2DBC `DatabaseClient`:

```java
import org.fireflyframework.security.adapter.r2dbc.R2dbcRevocationAdapter;
import org.fireflyframework.security.spi.RevocationPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.r2dbc.core.DatabaseClient;

@Configuration
class SecurityRevocationConfig {

    @Bean
    RevocationPort revocationPort(DatabaseClient databaseClient) {
        return new R2dbcRevocationAdapter(databaseClient);
    }
}
```

Application code (or the resource server) then uses the port:

```java
// Revoke a token until its own expiry (e.g. on logout)
revocationPort.revoke(jti, accessTokenExpiry).then(...);

// Fail-closed check during bearer validation
revocationPort.isRevoked(jti)
        .flatMap(revoked -> revoked ? Mono.error(new TokenRevokedException()) : continueChain());
```

With `spring.r2dbc.*` configured and the `security_revoked_token` table present, no further setup is needed.

## Dependencies

Compile scope (kept deliberately minimal — one capability, no vendor lock-in beyond R2DBC):

- `fireflyframework-security-api` — neutral security domain.
- `fireflyframework-security-spi` — defines `RevocationPort`.
- `spring-r2dbc` — provides `DatabaseClient`.
- `slf4j-api`, `lombok` (provided).

Test scope only: `spring-boot-starter-data-r2dbc`, `spring-boot-starter-test`, `r2dbc-postgresql`, `testcontainers` (`postgresql` + `junit-jupiter`), and `reactor-test`.

## Testing

`R2dbcRevocationAdapterIntegrationTest` is a **real end-to-end integration test** — no mocks, no in-memory stand-in. It boots a `@SpringBootTest` against a live **PostgreSQL 16** instance started by **Testcontainers** (`postgres:16-alpine`, Docker required), wires `spring.r2dbc.*` from the container via `@DynamicPropertySource`, and loads the schema through `spring.sql.init.mode=always`.

The test exercises the full contract of the adapter:

- a revoked, unexpired token reports `isRevoked == true`;
- an unknown token reports `false` (the not-revoked default);
- an entry whose `expires_at` is in the past no longer counts as revoked;
- `revoke` is an idempotent upsert (revoking the same `token_id` twice updates, not duplicates).

It is named `*Test` so it runs under Surefire — the module does not bind the Failsafe plugin. Running the suite requires a working Docker environment.

```bash
mvn -pl fireflyframework-security-adapter-r2dbc test
```

## Documentation

- Firefly Framework documentation hub and module catalog: [github.com/fireflyframework](https://github.com/fireflyframework)
- Driven-port contract: `fireflyframework-security-spi` (`RevocationPort`)
- Cache-backed alternative: `fireflyframework-security-adapter-redis`

## License

Copyright 2024-2026 Firefly Software Foundation.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
