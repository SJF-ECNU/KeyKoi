## ADDED Requirements

### Requirement: Bound credential delivery

KeyKoi SHALL keep signing keys in the daemon during SSH signing and require authentication before opening TLS proxy tunnels. Secret-bearing upstream connections SHALL use verified TLS by default.

#### Scenario: Key used through the agent

- **WHEN** an authorized SSH agent requests a signature
- **THEN** the daemon returns a signature without the raw signing material

#### Scenario: Proxy tunnel opened

- **WHEN** a caller establishes a TLS proxy tunnel
- **THEN** the proxy verifies the instance credential before any upstream connection

### Requirement: Consistent vault operations

KeyKoi SHALL serialize authorization commits with broker lock and session state, and collect encrypted backups from one consistent store view.

#### Scenario: Backup overlaps a write

- **WHEN** vault contents change while a backup is being collected
- **THEN** the backup reflects a single coherent store view
