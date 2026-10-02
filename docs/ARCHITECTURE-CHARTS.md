# Caddy — Architecture Charts

> Repository: `appolon1908/Caddy`
> Baseline branch: `main`
> Repository-local visual architecture. Keep these diagrams aligned with code, contracts and deployment.

## 1. System context
```mermaid
flowchart LR
 A["Internet clients"] --> C["Caddy<br/>TLS termination + host/path routing"]
 C --> K["Kong<br/>OIDC/JWT, scope, route and rate policy"]
 C --> O["oauth2-proxy<br/>community n8n editor gate"]
 C --> G["Grafana / Superset<br/>reviewed observability UI routes"]
 C --> B["OpenBao<br/>protected browser/API route"]
 K --> M["Middleware / owned application services"]
```

## 2. Internal component architecture
```mermaid
flowchart TB
 I["HTTPS listener"] --> TLS["TLS, host and source-network policy"]
 TLS --> HDR["Strip spoofable identity headers; preserve Authorization + trace headers"]
 HDR --> ROUTE["Host/path routing"]
 ROUTE --> K["Kong upstream"]
 ROUTE --> O["oauth2-proxy upstream"]
 ROUTE --> U["Reviewed direct UI/protected upstreams"]
 TLS --> OBS["Access logs, metrics and correlation data"]
```

## 3. Critical runtime flow
```mermaid
sequenceDiagram
 participant U as Client
 participant C as Caddy
 participant K as Kong
 participant P as Kong policy
 participant M as Middleware / upstream
 U->>C: HTTPS request + bearer token
 C->>K: Forward request, Authorization and trace headers
 K->>P: OIDC/JWT + scope + route + rate policy
 P-->>K: Allow / deny
 K->>M: Authorized upstream request
 M-->>K: Response
 K-->>C: Response
 C-->>U: TLS response
```

## 4. Deployment and promotion
```mermaid
flowchart LR
 F["Feature branch"] --> T["Tests / validation"]
 T --> PR["Pull request + review"]
 PR --> CI["CI green"]
 CI --> ST["Staging / isolated verification"]
 ST --> EX["Exact-SHA certification"]
 EX --> G{"Production approval?"}
 G -- No --> ST
 G -- Yes --> P["Production promotion"]
 P --> H["Health/readiness + rollback check"]
```

## 5. Observability and recovery
```mermaid
flowchart LR
 R["Caddy"] --> M["Caddy metrics"]
 R --> L["Access/security logs"]
 R --> C["Correlation IDs + traceparent/tracestate propagation"]
 M --> O["Observability stack"]
 L --> O
 C -. "headers forwarded; Caddy does not emit spans" .-> K["Kong / downstream tracing"]
 O --> A["Dashboards / alerts"]
 R --> B["Caddyfile + site/snippet/config snapshot"]
 B --> RR["Validate + reload/rollback rehearsal"]
```

## Ownership notes
- **Role:** Public TLS edge and reverse proxy
- **Primary boundary:** TLS termination, host/path/source-network policy and proxy handoff; application authentication remains downstream.
- **State/config:** Caddyfile, site blocks, snippets and edge contracts.
- **Dependencies/consumers:** Kong, oauth2-proxy, Grafana, Superset, OpenBao and explicitly reviewed upstreams.
- Caddy preserves bearer and trace headers for downstream policy; it does **not** claim an application tracing exporter.
- Cross-repository effects must use reviewed contracts; production effects remain separately gated.
