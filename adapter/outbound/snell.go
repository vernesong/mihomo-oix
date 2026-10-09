package outbound

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/ech/echparser"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowtls"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	"github.com/metacubex/mihomo/transport/snell"
	quicDialer "github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/quic-go"
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
	echTLSTransport       string
	http3                 *snell.HTTP3Client
	http3RetryAfter       atomic.Int64
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
	Transport         string `obfs:"transport,omitempty"`
	ALPN              string `obfs:"alpn,omitempty"`
	Protocol          string `obfs:"protocol,omitempty"`
	IdentityVersion   int    `obfs:"identity-version,omitempty"`
	LegacyFallback    bool   `obfs:"legacy-fallback,omitempty"`
	Preconnect        int    `obfs:"preconnect,omitempty"`
	Host              string `obfs:"host,omitempty"`
	SNI               string `obfs:"sni,omitempty"`
	ECHConfig         string `obfs:"ech-config,omitempty"`
	ECHConfigFile     string `obfs:"ech-config-file,omitempty"`
	CAFile            string `obfs:"ca-file,omitempty"`
	Insecure          bool   `obfs:"insecure,omitempty"`
	Fingerprint       string `obfs:"fingerprint,omitempty"`
	ClientFingerprint string `obfs:"client-fingerprint,omitempty"`
	Certificate       string `obfs:"certificate,omitempty"`
	PrivateKey        string `obfs:"private-key,omitempty"`
	SkipCertVerify    bool   `obfs:"skip-cert-verify,omitempty"`
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

const (
	defaultSnellECHTLSClientFingerprint = "chrome"
	snellECHTLSSessionCacheCapacity     = 32
	snellECHTLSPreconnectTimeout        = 10 * time.Second
)

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
	fingerprint := opt.ClientFingerprint
	if fingerprint == "" {
		fingerprint = option.ClientFingerprint
	}
	if fingerprint == "" {
		return defaultSnellECHTLSClientFingerprint
	}
	if strings.EqualFold(fingerprint, "none") {
		// Without a uTLS fingerprint crypto/tls copies the inner ALPN
		// (snell-ech/1) into the ClientHelloOuter, which is sent in the clear
		// and would identify every connection to a passive observer.
		log.Warnln("[Snell] %s ignores client-fingerprint none, using %s", snellECHTLSALPN, defaultSnellECHTLSClientFingerprint)
		return defaultSnellECHTLSClientFingerprint
	}
	return fingerprint
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
	if s.echTLSTransport == "h3" {
		return nil, errors.New("snell HTTP/3 requires a UDP dialer; a TCP stream cannot carry QUIC")
	}
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
		c, err := s.pool.GetContext(ctx)
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

	c, err := s.dialSnell(ctx)
	if err != nil {
		return nil, err
	}
	if err = s.writeHeaderContext(ctx, c, metadata); err != nil {
		_ = c.Close()
		return nil, err
	}
	return NewConn(c, s), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Snell) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = s.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	c, err := s.dialSnell(ctx)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	err = s.writeHeaderContext(ctx, c, metadata)
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

func (s *Snell) Close() error {
	if s.http3 != nil {
		return s.http3.Close()
	}
	return s.Base.Close()
}

func (s *Snell) dialSnell(ctx context.Context) (*snell.Snell, error) {
	if s.http3 != nil && (s.echTLSTransport == "h3" || time.Now().UnixNano() >= s.http3RetryAfter.Load()) {
		timeout := snellECHTLSPreconnectTimeout
		if s.echTLSTransport == "auto" {
			timeout = 2 * time.Second
		}
		h3ctx, cancel := context.WithTimeout(ctx, timeout)
		conn, exporter, err := s.http3.Open(h3ctx)
		cancel()
		if err == nil {
			return snell.StreamConnWithExporterIdentity(conn, s.psk, s.version, exporter), nil
		}
		if s.echTLSTransport == "h3" || ctx.Err() != nil {
			return nil, err
		}
		// A failed H3 establishment sent no Snell data. Use verified TCP for
		// this request and avoid delaying every new request on blocked UDP.
		s.http3RetryAfter.Store(time.Now().Add(30 * time.Second).UnixNano())
	}
	conn, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}
	stream, err := s.streamConnContext(ctx, conn)
	if err != nil {
		_ = conn.Close()
	}
	return stream, err
}

func (s *Snell) dialHTTP3(ctx context.Context) (*quic.Conn, error) {
	config, err := s.echTLS.ToStdConfig()
	if err != nil {
		return nil, err
	}
	config.MinVersion = tls.VersionTLS13
	config.NextProtos = []string{"h3"}
	if err = s.echTLS.ECH.ClientHandle(ctx, config); err != nil {
		return nil, err
	}
	_, conn, err := quicDialer.DialQuic(ctx, s.addr, s.DialOptions(), s.dialer, config, snellHTTP3QUICConfig(), quicDialer.DialQuicOption{})
	return conn, err
}

// snellHTTP3QUICConfig lets quic-go grow each receive window from its initial size
// while the stream is read, up to 4 MiB per stream and 16 MiB per connection as the
// native clients use: through a clean 200 Mbit/s link a 256 KiB stream window carried
// 32 Mbit/s at a 50 ms round trip and 10 Mbit/s at 150 ms, and 4 MiB fills the link.
func snellHTTP3QUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 30 * time.Second,
		KeepAlivePeriod: 10 * time.Second, MaxIncomingStreams: -1, MaxIncomingUniStreams: 3,
		InitialStreamReceiveWindow: 64 * 1024, MaxStreamReceiveWindow: 4 * 1024 * 1024,
		InitialConnectionReceiveWindow: 1024 * 1024, MaxConnectionReceiveWindow: 16 * 1024 * 1024,
	}
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
	echTLSTransport := "tcp"
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
		if opt.Transport != "" {
			echTLSTransport = opt.Transport
		}
		switch echTLSTransport {
		case "tcp":
		case "h3", "auto":
			if opt.IdentityVersion != 2 || opt.LegacyFallback {
				return nil, errors.New("snell HTTP/3 requires identity-version 2 without legacy-fallback")
			}
		default:
			return nil, fmt.Errorf("unsupported snell ech-tls transport: %s", echTLSTransport)
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
	if echTLSTransport != "tcp" && option.Version != snell.Version4 {
		return nil, errors.New("snell HTTP/3 requires version 4")
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
		echTLSTransport:       echTLSTransport,
		identity:              option.Identity,
		version:               option.Version,
		reuse:                 reuse,
	}
	s.dialer = option.NewDialer(s.DialOptions())
	if echTLSTransport != "tcp" {
		hash := sha256.Sum256(psk)
		s.http3 = &snell.HTTP3Client{Host: echTLSOpt.Host, Path: fmt.Sprintf("/ws-tunnel-%x", hash[:12]), Dial: s.dialHTTP3}
	}

	if s.reuse {
		s.pool = snell.NewPool(func(ctx context.Context) (*snell.Snell, error) {
			sc, err := s.dialSnell(ctx)
			if err != nil {
				return nil, err
			}
			if s.version == snell.Version4 {
				if err = sc.WarmupContext(ctx); err != nil {
					_ = sc.Close()
					return nil, err
				}
			}
			return sc, nil
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
