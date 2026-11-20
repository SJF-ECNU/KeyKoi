## ADDED Requirements

### Requirement: Non-model service credential support

KeyKoi SHALL maintain generic business credential flows and SHALL exclude model service API keys from dedicated integrations, documentation and acceptance coverage.

#### Scenario: A gateway client uses a supported business authentication flow

- **WHEN** a configured business client submits a valid KeyKoi session through a supported gateway header
- **THEN** the gateway forwards the request using the configured business credential

#### Scenario: A client sends only a retired session header

- **WHEN** the only KeyKoi session token is supplied in the retired model-specific header
- **THEN** the gateway rejects the request before upstream forwarding
