package ssha

import (
	"context"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh/agent"

	"keykoi/internal/model"
	"keykoi/internal/osruntime"
)

// Server 在受保护的 Unix socket 上提供 SSH agent 协议。
//
// socket 目录以 0700 创建、socket 文件以 0600 创建，并在 Accept 时校验对端
// 用户为当前用户（复用 internal/osruntime.ListenUnix）。
type Server struct {
	path  string
	agent agent.Agent

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
}

// NewServer 构造 agent 服务端。path 为 Unix socket 路径。
func NewServer(path string, a agent.Agent) *Server {
	return &Server{path: path, agent: a, conns: map[net.Conn]struct{}{}}
}

// Path 返回 agent socket 路径。
func (s *Server) Path() string { return s.path }

// Listen 建立只允许当前用户连接的本地监听。
func (s *Server) Listen() error {
	if s.path == "" {
		return model.NewError(model.CodeControlUnavailable, "ssh agent socket path is required")
	}
	ln, err := osruntime.ListenUnix(s.path)
	if err != nil {
		return model.WrapError(model.CodeControlUnavailable, err, "listen ssh agent socket")
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	return nil
}

// Serve 接受连接直到 Close。Close 之后的返回值为 nil。
func (s *Server) Serve() error {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln == nil {
		return model.NewError(model.CodeControlUnavailable, "ssh agent is not listening")
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			return model.WrapError(model.CodeControlUnavailable, err, "accept ssh agent connection")
		}
		if !s.track(conn) {
			_ = conn.Close()
			return nil
		}
		go s.serveConn(conn)
	}
}

// Run 在 ctx 结束时关闭服务；它阻塞到服务退出。
func (s *Server) Run(ctx context.Context) error {
	if err := s.Listen(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		_ = s.Close()
	}()
	err := s.Serve()
	close(done)
	return err
}

// Close 停止监听、关闭现存连接并删除 socket 文件。
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.conns = map[net.Conn]struct{}{}
	s.mu.Unlock()

	var firstErr error
	if ln != nil {
		if err := ln.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if s.path != "" {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) serveConn(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()
	// ServeAgent 只处理协议帧；任何错误都结束本连接。
	_ = agent.ServeAgent(s.agent, conn)
}

func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
