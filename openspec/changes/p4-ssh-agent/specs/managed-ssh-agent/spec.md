## ADDED Requirements

### Requirement: 受限 SSH 签名

SSH Agent SHALL 在签名许可有效时向 SSH 客户端提供兼容签名，私钥只由受信组件处理。

#### Scenario: 真实 SSH 认证与撤销

- **WHEN** 受许可的客户端认证，随后签名许可被撤销
- **THEN** 首次认证成功，下一次需要签名的认证被拒，既有连接行为按实际结果登记
