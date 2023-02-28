package transocks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
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

	var reader io.Reader = tc

	// Check if TLS
	isTLS, reader_n, err := peekSSL(tc)
	if err != nil {
		fields[log.FnError] = err.Error()
		s.logger.Error("peekSSL failed", fields)
		return
	}
	reader = reader_n
	fields["is_tls"] = isTLS

	if isTLS {
		// Peek ClientHello message from conn and returns SNI.
		hello, reader_n2, err := peekClientHello(reader)
		if err != nil {
			fields[log.FnError] = err.Error()
			s.logger.Error("peekClientHello failed", fields)
			return
		}
		if err == nil && hello.ServerName != "" {
			addr = hello.ServerName + addr[strings.Index(addr, ":"):]
		}
		reader = reader_n2
	} else {
		// Get HOST Header if http
		host, reader_n3, err := peekHTTP(reader)
		if err != nil {
			fields[log.FnError] = err.Error()
			s.logger.Error("peekHTTP failed", fields)
			return
		}
		if err == nil && host != "" {
			addr = host + addr[strings.Index(addr, ":"):]
		}
		reader = reader_n3
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
		_, err := io.CopyBuffer(destConn, reader, buf)
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

// Peek ClientHello message from conn and returns SNI.
func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	hello, err := readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}
	return hello, io.MultiReader(peekedBytes, reader), nil
}

func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	err := tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake() // Handshake() always returns error, but we can get ClientHelloInfo from GetConfigForClient.

	if hello == nil {
		return nil, err
	}

	return hello, nil
}

type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

// Check if tcp connection is SSL/TLS. Leave all bytes untouched by using TeeReader.
// Peek ClientHello message from conn and returns SNI.
func peekSSL(reader io.Reader) (bool, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	isTLS, err := isTLS(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return false, nil, err
	}
	return isTLS, io.MultiReader(peekedBytes, reader), nil
}

func isTLS(reader io.Reader) (bool, error) {
	buf := make([]byte, 1)
	_, err := reader.Read(buf)
	if err != nil {
		return false, err
	}
	return buf[0] == 0x16, nil
}

// Get HOST Header if http. Leave all bytes untouched by using TeeReader.
func peekHTTP(reader io.Reader) (string, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	host, err := getHost(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return "", nil, err
	}
	return host, io.MultiReader(peekedBytes, reader), nil
}

// Return the HOST from http headers.
func getHost(reader io.Reader) (string, error) {
	req, err := http.ReadRequest(bufio.NewReader(reader))
	if err != nil {
		return "", err
	}
	return req.Host, nil
}
