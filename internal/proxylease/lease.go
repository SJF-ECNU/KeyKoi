// Package proxylease keeps an adapter's execution tied to its original lease.
package proxylease

import (
	"context"
	"errors"
	"net"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/ipcclient"
	"keykoi/internal/model"
	"keykoi/internal/secret"
)

const Interval = time.Second

type Authority interface {
	Authorize(context.Context, broker.Request) (*broker.Authorization, error)
	CheckLease(context.Context, secret.Value, model.UseLease) error
	ReleaseLease(string)
}

type Use struct {
	ctx      context.Context
	cancel   func()
	control  Authority
	token    secret.Value
	lease    model.UseLease
	last     time.Time
	Interval time.Duration
}

// Authorize obtains the credential and target from one database proxy decision.
func Authorize(ctx context.Context, control Authority, token secret.Value, bindingID string, timeout time.Duration) (*broker.Authorization, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return control.Authorize(ctx, broker.Request{
		Token: token, BindingID: bindingID, Mode: model.ModeProxy, Purpose: "database proxy",
	})
}

// Begin keeps the execution tied to the original lease and its deadline.
func Begin(control Authority, token secret.Value, authz *broker.Authorization, interval time.Duration) (*Use, error) {
	if authz == nil || authz.Lease.ID == "" || authz.Lease.UseLeaseExpiresAt.IsZero() {
		return nil, model.NewError(model.CodeLeaseExpired, "missing execution lease")
	}
	ctx, cancel := authz.ExecutionContext(context.Background())
	return &Use{control: control, token: token, lease: authz.Lease, last: time.Now(), Interval: interval, ctx: ctx, cancel: cancel}, nil
}

// Binding validates the authorized snapshot without a separate target lookup.
func Binding(authz *broker.Authorization, bindingID string) (*model.Binding, error) {
	if authz == nil || authz.Binding == nil {
		return nil, errors.New("authorization returned no binding snapshot")
	}
	binding := authz.Binding
	switch {
	case binding.ID != "" && binding.ID != bindingID:
		return nil, errors.New("authorization returned a binding snapshot for another binding")
	case binding.Status != "" && binding.Status != model.StatusActive:
		return nil, errors.New("binding is " + string(binding.Status))
	}
	return binding, nil
}

// ErrorCode reads stable codes from both local and IPC authorities.
func ErrorCode(err error) model.Code {
	var apiErr *ipcclient.APIError
	if errors.As(err, &apiErr) {
		return model.Code(apiErr.Code)
	}
	return model.CodeOf(err)
}

// Denial maps authorization failures to messages safe to return to database clients.
func Denial(err error) error {
	switch ErrorCode(err) {
	case model.CodeSessionInvalid, model.CodeUseNotAllowed, model.CodeLeaseExpired:
		return errors.New("session token is not authorized to use this binding")
	case model.CodeBindingDisabled:
		return errors.New("binding is not available")
	case model.CodeVaultLocked:
		return errors.New("keykoi vault is locked")
	case model.CodeCredentialUnavailable:
		return errors.New("credential is unavailable")
	default:
		return errors.New("keykoid resolve failed")
	}
}

func (u *Use) Finish() {
	u.cancel()
	u.control.ReleaseLease(u.lease.ID)
}

// Track closes a socket on explicit revocation or absolute expiration,
// including while a peer stalls halfway through a message.
func (u *Use) Track(conn net.Conn) func() bool {
	return context.AfterFunc(u.ctx, func() { _ = conn.Close() })
}

func (u *Use) Context() context.Context { return u.ctx }

// Changed only treats explicit denials as revocations. A transient control failure
// never renews the lease and cannot bypass the local expiry timer.
func (u *Use) Changed() bool {
	now := time.Now()
	if u.lease.Expired(now) {
		return true
	}
	if now.Before(u.last.Add(u.Interval)) {
		return false
	}
	u.last = now
	ctx, cancel := context.WithTimeout(u.ctx, u.Interval)
	defer cancel()
	switch ErrorCode(u.control.CheckLease(ctx, u.token, u.lease)) {
	case model.CodeLeaseExpired, model.CodeSessionInvalid, model.CodeBindingDisabled,
		model.CodeCredentialUnavailable, model.CodeUseNotAllowed, model.CodeVaultLocked:
		return true
	}
	return u.lease.Expired(time.Now())
}
