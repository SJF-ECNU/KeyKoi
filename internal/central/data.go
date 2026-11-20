package central

import (
	"context"
	"fmt"
	"time"
)

// policyRecord 是 binding_policy 中一行策略。
type policyRecord struct {
	// PrincipalID 为空只表示旧版空主体策略，不代表任意主体通配。
	PrincipalID       string
	CredentialID      string
	CredentialVersion int
	Mode              string
	Status            string
}

// leaseRecord 是 leases 中判定一次许可所需的字段。
type leaseRecord struct {
	Epoch             string
	Status            string
	BindingID         string
	PrincipalID       string
	Mode              string
	CredentialVersion int
	ExpiresAt         time.Time
}

// dataStore 抽象中心用到的数据库操作。生产实现是 PostgreSQL，测试可注入
// 内存实现，从而在没有数据库的环境里做处理器级验证。
type dataStore interface {
	RegisterDevice(ctx context.Context, id, name, secretHash string, at time.Time) error
	Device(ctx context.Context, id string) (secretHash, status string, err error)
	DeviceStatus(ctx context.Context, id string) (string, error)

	UpsertPolicy(ctx context.Context, bindingID string, p policyRecord) error
	Policy(ctx context.Context, bindingID string) (policyRecord, error)
	BindingStatus(ctx context.Context, bindingID string) (string, error)

	InsertLease(ctx context.Context, l Lease) error
	Lease(ctx context.Context, leaseID, deviceID string) (leaseRecord, error)

	RevokeDevice(ctx context.Context, target string, at time.Time, epoch string) error
	RevokeBinding(ctx context.Context, target string, at time.Time, epoch string) error
	CountRevocations(ctx context.Context, epoch, deviceID, bindingID string) (int, error)
	Events(ctx context.Context, since int64) ([]Revocation, error)
}

// data 返回本次请求使用的数据访问层。
func (s *Server) data() (dataStore, error) {
	if s.store != nil {
		return s.store, nil
	}
	if s.DB == nil {
		return nil, fmt.Errorf("central server has no database")
	}
	return sqlData{db: s.DB}, nil
}
