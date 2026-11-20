## ADDED Requirements

### Requirement: IPC control honors object ownership

The daemon SHALL allow IPC session closure and lease revocation only for the owning local subject or an authenticated administrator. It SHALL require administrator authentication for the full audit stream.

#### Scenario: Local subject cleans up its own execution

- **WHEN** the subject that created a session closes it or revokes its lease
- **THEN** the daemon completes the operation

#### Scenario: A different subject requests cleanup

- **WHEN** a non-administrator requests cleanup for a session or lease owned by another subject
- **THEN** the daemon denies the operation and preserves the object

#### Scenario: Administrator reads audit or cleans up execution

- **WHEN** an authenticated administrator requests the audit stream or cleans up a session or lease
- **THEN** the daemon allows the operation

### Requirement: MongoDB upstream uses verified TLS by default

The MongoDB adapter SHALL verify the upstream certificate chain and registered hostname before sending MongoDB traffic. It SHALL require explicit operator authorization for plaintext, and an HTTPS target SHALL retain TLS regardless of the plaintext option.

#### Scenario: Server uses a trusted private CA

- **WHEN** the operator configures the CA and the server certificate matches the registered host
- **THEN** the proxy negotiates TLS before it exchanges hello or authentication messages

#### Scenario: TLS verification fails

- **WHEN** the upstream certificate is invalid for the registered address
- **THEN** the proxy terminates without sending MongoDB traffic or retrying over plaintext

#### Scenario: Local plaintext development service

- **WHEN** the operator explicitly enables plaintext for a MongoDB target that does not require TLS
- **THEN** the adapter can connect to that service and continue to require session and SCRAM authentication
