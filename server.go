package transocks

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cybozu-go/log"
	"github.com/cybozu-go/netutil"
	"github.com/cybozu-go/well"
	"golang.org/x/net/proxy"
)

const (
	keepAliveTimeout = 3 * time.Minute
	copyBufferSize   = 64 << 10
)

// Listeners returns a list of net.Listener.
func Listeners(c *Config) ([]net.Listener, error) {
	ln, err := net.Listen("tcp", c.Addr)
	if err != nil {
		return nil, err
	}
	return []net.Listener{ln}, nil
}

// Server provides transparent proxy server functions.
type Server struct {
	well.Server
	mode   Mode
	logger *log.Logger
	dialer proxy.Dialer
	pool   sync.Pool
}

// NewServer creates Server.
// If c is not valid, this returns non-nil error.
func NewServer(c *Config) (*Server, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}

	dialer := c.Dialer
	if dialer == nil {
		dialer = &net.Dialer{
			KeepAlive: keepAliveTimeout,
			DualStack: true,
		}
	}
	pdialer, err := proxy.FromURL(c.ProxyURL, dialer)
	if err != nil {
		return nil, err
	}
	logger := c.Logger
	if logger == nil {
		logger = log.DefaultLogger()
	}

	s := &Server{
		Server: well.Server{
			ShutdownTimeout: c.ShutdownTimeout,
			Env:             c.Env,
		},
		mode:   c.Mode,
		logger: logger,
		dialer: pdialer,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, copyBufferSize)
			},
		},
	}
	s.Server.Handler = s.handleConnection
	return s, nil
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		s.logger.Error("non-TCP connection", map[string]interface{}{
			"conn": conn,
		})
		return
	}

	fields := well.FieldsFromContext(ctx)
	fields[log.FnType] = "access"
	fields["client_addr"] = conn.RemoteAddr().String()

	var addr string
	switch s.mode {
	case ModeNAT:
		origAddr, err := GetOriginalDST(tc)
		if err != nil {
			fields[log.FnError] = err.Error()
			s.logger.Error("GetOriginalDST failed", fields)
			return
		}
		addr = origAddr.String()
	default:
		addr = tc.LocalAddr().String()
	}
	fields["dest_addr"] = addr

	destConn, err := s.dialer.Dial("tcp", addr)
	if err != nil {
		fields[log.FnError] = err.Error()
		s.logger.Error("failed to connect to proxy server", fields)
		return
	}
	defer destConn.Close()

	s.logger.Info("proxy starts", fields)

	// do proxy
	st := time.Now()
	env := well.NewEnvironment(ctx)
	env.Go(func(ctx context.Context) error {
		buf := s.pool.Get().([]byte)
		_, err := io.CopyBuffer(destConn, tc, buf)
		s.pool.Put(buf)
		if hc, ok := destConn.(netutil.HalfCloser); ok {
			hc.CloseWrite()
		}
		tc.CloseRead()
		return err
	})
	env.Go(func(ctx context.Context) error {
		buf := s.pool.Get().([]byte)
		_, err := io.CopyBuffer(tc, destConn, buf)
		s.pool.Put(buf)
		tc.CloseWrite()
		if hc, ok := destConn.(netutil.HalfCloser); ok {
			hc.CloseRead()
		}
		return err
	})
	env.Stop()
	err = env.Wait()

	fields = well.FieldsFromContext(ctx)
	fields["elapsed"] = time.Since(st).Seconds()
	if err != nil {
		fields[log.FnError] = err.Error()
		s.logger.Error("proxy ends with an error", fields)
		return
	}
	s.logger.Info("proxy ends", fields)
}
