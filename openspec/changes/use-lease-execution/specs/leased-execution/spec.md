## ADDED Requirements

### Requirement: Execution lifetime

Database connections SHALL keep the original use lease until the connection ends and SHALL terminate once that lease expires.

#### Scenario: Center is unreachable

- **WHEN** the daemon cannot contact the configured center
- **THEN** it enforces the original absolute lease expiration

### Requirement: Caller-scoped HTTPS proxy

HTTPS proxy requests SHALL use the authenticated calling session and leave secret material within the daemon.

#### Scenario: An authorized tool uses a CONNECT tunnel

- **WHEN** a tool provides its valid session and has a proxy grant for the destination
- **THEN** it receives the upstream response through the proxy


### Requirement: Explicit material delivery

A tool that needs raw material SHALL present a runtime_delivery grant. The daemon SHALL enforce any configured Binding field allowlist.

#### Scenario: A binding allows one field

- **WHEN** a runtime delivery request uses a binding that allows one credential field
- **THEN** the daemon exposes only that field
