package model

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// ServiceProtocol distinguishes explicit database and SSH targets from HTTP.
type ServiceProtocol string

const (
	ProtocolHTTP     ServiceProtocol = "http"
	ProtocolPostgres ServiceProtocol = "postgres"
	ProtocolRedis    ServiceProtocol = "redis"
	ProtocolMySQL    ServiceProtocol = "mysql"
	ProtocolMongo    ServiceProtocol = "mongo"
	ProtocolSSH      ServiceProtocol = "ssh"
)

type ServiceTarget struct {
	Protocol ServiceProtocol
	Host     string
	Port     string
	TLS      bool
}

func (t ServiceTarget) Address() string {
	return net.JoinHostPort(t.Host, t.Port)
}

func targetScheme(scheme string) (ServiceProtocol, bool) {
	switch scheme {
	case "http":
		return ProtocolHTTP, false
	case "https":
		return ProtocolHTTP, true
	case "postgres", "postgresql":
		return ProtocolPostgres, false
	case "redis":
		return ProtocolRedis, false
	case "rediss", "redis+tls":
		return ProtocolRedis, true
	case "mysql":
		return ProtocolMySQL, false
	case "mongodb":
		return ProtocolMongo, false
	case "ssh":
		return ProtocolSSH, false
	default:
		return "", false
	}
}

// Target parses the registered address. Transport policy is enforced by the
// executor, which can require verified TLS independently of the URI scheme.
func (b Binding) Target() (ServiceTarget, error) {
	u, err := url.Parse(b.UpstreamOrigin)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return ServiceTarget{}, fmt.Errorf("binding %s: invalid upstream address", b.ID)
	}
	protocol, tls := targetScheme(u.Scheme)
	if protocol == "" {
		return ServiceTarget{}, fmt.Errorf("binding %s: unsupported upstream scheme %q", b.ID, u.Scheme)
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ServiceTarget{}, fmt.Errorf("binding %s: invalid upstream port", b.ID)
		}
	}
	if protocol != ProtocolHTTP && ((u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "") {
		return ServiceTarget{}, fmt.Errorf("binding %s: upstream address must contain only a host and optional port", b.ID)
	}
	return ServiceTarget{Protocol: protocol, Host: u.Hostname(), Port: port, TLS: tls}, nil
}

// DatabaseTarget accepts the legacy HTTP-shaped target as well as a matching
// native scheme. An explicitly typed binding cannot be dialed as another protocol.
func (b Binding) DatabaseTarget(protocol ServiceProtocol, defaultPort string) (ServiceTarget, error) {
	target, err := b.Target()
	if err != nil {
		return ServiceTarget{}, err
	}
	if target.Protocol != ProtocolHTTP && target.Protocol != protocol {
		return ServiceTarget{}, fmt.Errorf("binding %s: expected a %s target", b.ID, protocol)
	}
	if target.Port == "" {
		target.Port = defaultPort
	}
	return target, nil
}
