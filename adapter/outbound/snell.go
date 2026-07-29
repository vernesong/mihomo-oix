package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/ech/echparser"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowtls"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	"github.com/metacubex/mihomo/transport/snell"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
)

type Snell struct {
	*Base
	option                *SnellOption
	psk                   []byte
	pool                  *snell.Pool
	obfsOption            *simpleObfsOption
	shadowTLSOption       *shadowtls.ShadowTLSOption
	restlsConfig          *restls.Config
	jlsConfig             *jls.ClientConfig
	echTLS                *vmess.TLSConfig
	echTLSIdentityVersion int
	echTLSLegacyFallback  bool
	identity              bool
	version               int
	reuse                 bool
}

type SnellOption struct {
	BasicOption
	Name              string         `proxy:"name"`
	Server            string         `proxy:"server"`
	Port              int            `proxy:"port"`
	Psk               string         `proxy:"psk"`
	UDP               bool           `proxy:"udp,omitempty"`
	Version           int            `proxy:"version,omitempty"`
	Reuse             bool           `proxy:"reuse,omitempty"`
	Identity          bool           `proxy:"identity,omitempty"`
	ObfsOpts          map[string]any `proxy:"obfs-opts,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
}

type snellECHTLSObfsOption struct {
	ALPN              string            `obfs:"alpn,omitempty"`
	Protocol          string            `obfs:"protocol,omitempty"`
	IdentityVersion   int               `obfs:"identity-version,omitempty"`
	LegacyFallback    bool              `obfs:"legacy-fallback,omitempty"`
	Preconnect        int               `obfs:"preconnect,omitempty"`
	Host              string            `obfs:"host,omitempty"`
	SNI               string            `obfs:"sni,omitempty"`
	Path              string            `obfs:"path,omitempty"`
	ECHConfig         string            `obfs:"ech-config,omitempty"`
	ECHConfigFile     string            `obfs:"ech-config-file,omitempty"`
	CAFile            string            `obfs:"ca-file,omitempty"`
	Insecure          bool              `obfs:"insecure,omitempty"`
	Fingerprint       string            `obfs:"fingerprint,omitempty"`
	ClientFingerprint string            `obfs:"client-fingerprint,omitempty"`
	Certificate       string            `obfs:"certificate,omitempty"`
	PrivateKey        string            `obfs:"private-key,omitempty"`
	Headers           map[string]string `obfs:"headers,omitempty"`
	SkipCertVerify    bool              `obfs:"skip-cert-verify,omitempty"`
}

func snellECHTLSHost(opt *snellECHTLSObfsOption, server string) string {
	if opt.SNI != "" {
		return opt.SNI
	}
	if opt.Host != "" {
		return opt.Host
	}
	return server
}

const defaultSnellECHTLSClientFingerprint = "chrome"
const snellECHTLSSessionCacheCapacity = 32
const snellECHTLSPreconnectTimeout = 10 * time.Second
const (
	snellECHTLSALPN         = "snell-ech/1"
	snellECHTLSPreviousALPN = "oix-snell/1"
	snellECHTLSLegacyALPN   = "h2"
)

func resolveSnellECHTLSALPN(alpn, protocol string) (string, error) {
	if protocol == snellECHTLSPreviousALPN {
		protocol = snellECHTLSALPN
	}
	if alpn != "" && protocol != "" && alpn != protocol {
		return "", errors.New("ech-tls alpn and legacy protocol values conflict")
	}
	if alpn == "" {
		alpn = protocol
	}
	if alpn == "" {
		alpn = snellECHTLSALPN
	}
	if alpn != snellECHTLSALPN {
		return "", fmt.Errorf("unsupported ech-tls ALPN: %s", alpn)
	}
	return alpn, nil
}

func resolveSnellECHTLSClientFingerprint(opt *snellECHTLSObfsOption, option SnellOption) string {
	if opt.ClientFingerprint != "" {
		return opt.ClientFingerprint
	}
	if option.ClientFingerprint != "" {
		return option.ClientFingerprint
	}
	return defaultSnellECHTLSClientFingerprint
}

func snellECHTLSConfig(opt *snellECHTLSObfsOption) (*ech.Config, error) {
	if opt.ECHConfig != "" && opt.ECHConfigFile != "" {
		return nil, fmt.Errorf("ech-config and ech-config-file are mutually exclusive")
	}
	if opt.ECHConfig == "" && opt.ECHConfigFile == "" {
		return nil, fmt.Errorf("ech-tls requires ech-config or ech-config-file")
	}

	var list []byte
	var err error
	if opt.ECHConfig != "" {
		list, err = base64.StdEncoding.DecodeString(strings.TrimSpace(opt.ECHConfig))
		if err != nil {
			return nil, fmt.Errorf("base64 decode ech-config failed: %w", err)
		}
	} else {
		path := C.Path.Resolve(opt.ECHConfigFile)
		if !C.Path.IsSafePath(path) {
			return nil, C.Path.ErrNotSafePath(path)
		}
		list, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read ech-config-file failed: %w", err)
		}
	}
	if configs, err := echparser.ParseECHConfigList(list); err != nil {
		return nil, fmt.Errorf("parse ech config list failed: %w", err)
	} else if len(configs) == 0 {
		return nil, fmt.Errorf("ech config list is empty")
	}

	return &ech.Config{
		GetEncryptedClientHelloConfigList: func(ctx context.Context, serverName string) ([]byte, error) {
			return list, nil
		},
	}, nil
}

func requiresSnellV4Identity(mode string) bool {
	return mode == "ech-tls"
}

func (s *Snell) streamConnContext(ctx context.Context, c net.Conn) (*snell.Snell, error) {
	var err error
	var tlsExporter []byte
	switch s.obfsOption.Mode {
	case "tls":
		c = obfs.NewTLSObfs(c, s.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(s.addr)
		c = obfs.NewHTTPObfs(c, s.obfsOption.Host, port)
	case shadowtls.Mode:
		c, err = shadowtls.NewShadowTLS(ctx, c, s.shadowTLSOption)
		if err != nil {
			return nil, err
		}
	case restls.Mode:
		c, err = restls.NewRestls(ctx, c, s.restlsConfig)
		if err != nil {
			return nil, err
		}
	case jls.Mode:
		c, err = jls.NewClient(ctx, c, s.jlsConfig)
		if err != nil {
			return nil, err
		}
	case "ech-tls":
		c, err = vmess.StreamTLSConn(ctx, c, s.echTLS)
		if err != nil {
			return nil, err
		}
		state := tlsC.GetTLSConnectionState(c)
		if !state.ECHAccepted {
			return nil, errors.New("snell ech-tls handshake did not accept ECH")
		}
		useExporterIdentity := state.NegotiatedProtocol == snellECHTLSALPN && s.echTLSIdentityVersion == 2
		if state.NegotiatedProtocol == snellECHTLSLegacyALPN && !s.echTLSLegacyFallback {
			return nil, errors.New("snell ech-tls legacy ALPN was not enabled")
		}
		if state.NegotiatedProtocol != snellECHTLSALPN && state.NegotiatedProtocol != snellECHTLSLegacyALPN {
			return nil, fmt.Errorf("snell ech-tls negotiated ALPN %q", state.NegotiatedProtocol)
		}
		if useExporterIdentity {
			tlsExporter, err = state.ExportKeyingMaterial(
				snell.IdentityExporterLabel,
				[]byte{},
				snell.IdentityExporterLength,
			)
			if err != nil {
				return nil, fmt.Errorf("snell ech-tls exporter: %w", err)
			}
		}
	}
	if s.identity && s.version == snell.Version4 {
		if len(tlsExporter) == snell.IdentityExporterLength {
			return snell.StreamConnWithExporterIdentity(c, s.psk, s.version, tlsExporter), nil
		}
		return snell.StreamConnWithIdentity(c, s.psk, s.version), nil
	}
	return snell.StreamConn(c, s.psk, s.version), nil
}

// StreamConnContext implements C.ProxyAdapter
func (s *Snell) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c, err := s.streamConnContext(ctx, c)
	if err != nil {
		return nil, err
	}
	err = s.writeHeaderContext(ctx, c, metadata)
	return c, err
}

func (s *Snell) writeHeaderContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	if metadata.NetWork == C.UDP {
		err = snell.WriteUDPHeader(c, s.version)
		if err == nil && s.version >= snell.Version4 {
			if sc, ok := c.(*snell.Snell); ok {
				err = sc.ReadReply()
			}
		}
		return
	}
	err = snell.WriteHeaderWithReuse(c, metadata.String(), uint(metadata.DstPort), s.version, s.reuse)
	return
}

// DialContext implements C.ProxyAdapter
func (s *Snell) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if s.reuse {
		c, err := s.pool.Get()
		if err != nil {
			return nil, err
		}

		if err = s.writeHeaderContext(ctx, c, metadata); err != nil {
			_ = c.Close()
			return nil, err
		}
		if pc, ok := c.(*snell.PoolConn); ok {
			pc.MarkReusable()
		}
		return NewConn(c, s), err
	}

	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = s.StreamConnContext(ctx, c, metadata)
	return NewConn(c, s), err
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Snell) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = s.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = s.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	pc := snell.PacketConn(c)
	return NewPacketConn(pc, s), nil
}

// SupportUOT implements C.ProxyAdapter
func (s *Snell) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (s *Snell) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func NewSnell(option SnellOption) (*Snell, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	psk := []byte(option.Psk)

	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	obfsOption := &simpleObfsOption{Host: "bing.com"}
	if err := decoder.Decode(option.ObfsOpts, obfsOption); err != nil {
		return nil, fmt.Errorf("snell %s initialize obfs error: %w", addr, err)
	}

	var shadowTLSOpt *shadowtls.ShadowTLSOption
	var restlsConfig *restls.Config
	var jlsConfig *jls.ClientConfig
	var echTLSOpt *vmess.TLSConfig
	echTLSIdentityVersion := 2
	echTLSLegacyFallback := false
	echTLSPreconnect := 0
	switch obfsOption.Mode {
	case "tls", "http", "":
		break
	case shadowtls.Mode:
		opt := &shadowTLSOption{
			Version: 2,
		}
		if err := decoder.Decode(option.ObfsOpts, opt); err != nil {
			return nil, fmt.Errorf("snell %s initialize shadow-tls-plugin error: %w", addr, err)
		}

		shadowTLSOpt = &shadowtls.ShadowTLSOption{
			Password:          opt.Password,
			Host:              opt.Host,
			Fingerprint:       opt.Fingerprint,
			Certificate:       opt.Certificate,
			PrivateKey:        opt.PrivateKey,
			ClientFingerprint: option.ClientFingerprint,
			SkipCertVerify:    opt.SkipCertVerify,
			NameCertVerify:    opt.NameCertVerify,
			Version:           opt.Version,
		}

		if opt.ALPN != nil {
			shadowTLSOpt.ALPN = opt.ALPN
		} else {
			shadowTLSOpt.ALPN = shadowtls.DefaultALPN
		}
	case restls.Mode:
		opt := &restlsOption{}
		if err := decoder.Decode(option.ObfsOpts, opt); err != nil {
			return nil, fmt.Errorf("snell %s initialize restls-plugin error: %w", addr, err)
		}

		var err error
		restlsConfig, err = restls.NewRestlsConfig(opt.Host, opt.Password, opt.VersionHint, opt.RestlsScript, option.ClientFingerprint)
		if err != nil {
			return nil, fmt.Errorf("snell %s initialize restls-plugin error: %w", addr, err)
		}
		restlsConfig.InsecureSkipVerify = opt.SkipCertVerify
		if opt.Fingerprint != "" {
			if err = restls.SetFingerprint(restlsConfig, opt.Fingerprint, opt.NameCertVerify); err != nil {
				return nil, fmt.Errorf("snell %s initialize restls-plugin error: %w", addr, err)
			}
		} else if opt.NameCertVerify != "" {
			restls.SetNameCertVerify(restlsConfig, opt.NameCertVerify)
		}
		restlsConfig.ForceTLS12 = opt.ForceTLS12
	case jls.Mode:
		opt := &jlsOption{}
		if err := decoder.Decode(option.ObfsOpts, opt); err != nil {
			return nil, fmt.Errorf("snell %s initialize jls-plugin error: %w", addr, err)
		}

		var err error
		jlsConfig, err = jls.NewClientConfig(opt.Host, opt.Username, opt.Password, opt.ALPN)
		if err != nil {
			return nil, fmt.Errorf("snell %s initialize jls-plugin error: %w", addr, err)
		}
		jlsConfig.ClientFingerprint = option.ClientFingerprint
	case "ech-tls":
		opt := &snellECHTLSObfsOption{}
		if err := decoder.Decode(option.ObfsOpts, opt); err != nil {
			return nil, fmt.Errorf("snell %s initialize ech-tls error: %w", addr, err)
		}
		host := snellECHTLSHost(opt, option.Server)
		alpn, err := resolveSnellECHTLSALPN(opt.ALPN, opt.Protocol)
		if err != nil {
			return nil, fmt.Errorf("snell %s %w", addr, err)
		}
		if opt.IdentityVersion == 0 {
			opt.IdentityVersion = 2
		}
		if opt.IdentityVersion != 1 && opt.IdentityVersion != 2 {
			return nil, fmt.Errorf("snell %s unsupported identity version: %d", addr, opt.IdentityVersion)
		}
		if opt.Preconnect < 0 || opt.Preconnect > 4 {
			return nil, fmt.Errorf("snell %s preconnect must be between 0 and 4", addr)
		}
		echTLSIdentityVersion = opt.IdentityVersion
		echTLSLegacyFallback = opt.LegacyFallback
		echTLSPreconnect = opt.Preconnect
		if opt.SkipCertVerify || opt.Insecure {
			return nil, fmt.Errorf("snell %s %s requires certificate verification", addr, snellECHTLSALPN)
		}
		echConfig, err := snellECHTLSConfig(opt)
		if err != nil {
			return nil, err
		}
		nextProtos := []string{alpn}
		if opt.LegacyFallback {
			nextProtos = append(nextProtos, snellECHTLSLegacyALPN)
		}
		echTLSOpt = &vmess.TLSConfig{
			Host:                 host,
			CAFile:               opt.CAFile,
			ClientFingerprint:    resolveSnellECHTLSClientFingerprint(opt, option),
			FingerPrint:          opt.Fingerprint,
			Certificate:          opt.Certificate,
			PrivateKey:           opt.PrivateKey,
			NextProtos:           nextProtos,
			ECH:                  echConfig,
			ClientSessionCache:   tls.NewLRUClientSessionCache(snellECHTLSSessionCacheCapacity),
			UClientSessionCache:  utls.NewLRUClientSessionCache(snellECHTLSSessionCacheCapacity),
			DisableRenegotiation: true,
		}
	default:
		return nil, fmt.Errorf("snell %s obfs mode error: %s", addr, obfsOption.Mode)
	}

	// backward compatible
	if option.Version == 0 {
		if requiresSnellV4Identity(obfsOption.Mode) {
			option.Version = snell.Version4
		} else {
			option.Version = snell.DefaultSnellVersion
		}
	}
	if option.Version == snell.Version5 {
		// Snell v5 servers are backward-compatible with v4 clients.
		option.Version = snell.Version4
	}
	if requiresSnellV4Identity(obfsOption.Mode) && option.Version == snell.Version4 {
		option.Identity = true
	}
	reuse := option.Version == snell.Version2 || (option.Version == snell.Version4 && option.Reuse)
	switch option.Version {
	case snell.Version1, snell.Version2:
		if option.UDP {
			return nil, fmt.Errorf("snell version %d not support UDP", option.Version)
		}
	case snell.Version3, snell.Version4:
	default:
		return nil, fmt.Errorf("snell version error: %d", option.Version)
	}

	s := &Snell{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Snell,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:                &option,
		psk:                   psk,
		obfsOption:            obfsOption,
		shadowTLSOption:       shadowTLSOpt,
		restlsConfig:          restlsConfig,
		jlsConfig:             jlsConfig,
		echTLS:                echTLSOpt,
		echTLSIdentityVersion: echTLSIdentityVersion,
		echTLSLegacyFallback:  echTLSLegacyFallback,
		identity:              option.Identity,
		version:               option.Version,
		reuse:                 reuse,
	}
	s.dialer = option.NewDialer(s.DialOptions())

	if s.reuse {
		s.pool = snell.NewPool(func(ctx context.Context) (*snell.Snell, error) {
			c, err := s.dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}

			stream, err := s.streamConnContext(ctx, c)
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			if s.version == snell.Version4 {
				if err = stream.Warmup(); err != nil {
					_ = stream.Close()
					return nil, err
				}
			}
			return stream, nil
		})
		if echTLSPreconnect > 0 {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), snellECHTLSPreconnectTimeout)
				defer cancel()
				s.pool.Warm(ctx, echTLSPreconnect)
			}()
		}
	}
	return s, nil
}
