# Metrics Contract v1

## Purpose

Caddy metrics should support operational incident response without exposing user-level identifiers or unbounded query values.

## Repository implementation status

The global metrics option enables native metrics on the private Admin API socket
(unix//run/caddy/admin.sock) and on the private :2020 listener that Prometheus
scrapes as caddy:2020; that listener binds CADDY_PRIVATE_METRICS_BIND only. Public
sites deny /metrics before routing. There is no public metrics handler and
per-host metrics are disabled. No request identifiers
are used as metric labels. Release SHA and configuration digest appear in logs.

## Recommended low-cardinality metrics

- request count
- response status class
- request duration
- TLS failures
- upstream failures
- active connections
- reload failures

## Prohibited labels

The metric contract must avoid labels containing:

- user ID
- token
- full arbitrary URL
- customer ID
- correlation ID
- unbounded query values

## Policy

Metrics remain edge-scoped. Monitoring systems may consume them, but they do not become part of Caddy’s routing or business control authority.
