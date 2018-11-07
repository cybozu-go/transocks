package transocks

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/cybozu-go/log"
	"github.com/cybozu-go/well"
)

const (
	defaultShutdownTimeout = 1 * time.Minute
)

// Mode is the type of transocks mode.
type Mode string

func (m Mode) String() string {
	return string(m)
}

const (
	// ModeNAT is mode constant for NAT.
	ModeNAT = Mode("nat")
)

// Config keeps configurations for Server.
type Config struct {
	// Addr is the listening address.
	Addr string

	// ProxyURL is the URL for upstream proxy.
	//
	// For SOCKS5, URL looks like "socks5://USER:PASSWORD@HOST:PORT".
	//
	// For HTTP proxy, URL looks like "http://USER:PASSWORD@HOST:PORT".
	// The HTTP proxy must support CONNECT method.
	ProxyURL *url.URL

	// Mode determines how clients are routed to transocks.
	// Default is ModeNAT.  No other options are available at this point.
	Mode Mode

	// ShutdownTimeout is the maximum duration the server waits for
	// all connections to be closed before shutdown.
	//
	// Zero duration disables timeout.  Default is 1 minute.
	ShutdownTimeout time.Duration

	// Dialer is the base dialer to connect to the proxy server.
	// The server uses the default dialer if this is nil.
	Dialer *net.Dialer

	// Logger can be used to provide a custom logger.
	// If nil, the default logger is used.
	Logger *log.Logger

	// Env can be used to specify a well.Environment on which the server runs.
	// If nil, the server will run on the global environment.
	Env *well.Environment
}

// NewConfig creates and initializes a new Config.
func NewConfig() *Config {
	c := new(Config)
	c.Mode = ModeNAT
	c.ShutdownTimeout = defaultShutdownTimeout
	return c
}

// validate validates the configuration.
// It returns non-nil error if the configuration is not valid.
func (c *Config) validate() error {
	if c.ProxyURL == nil {
		return errors.New("ProxyURL is nil")
	}
	if c.Mode != ModeNAT {
		return fmt.Errorf("Unknown mode: %s", c.Mode)
	}
	return nil
}
