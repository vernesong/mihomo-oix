package vmess

import (
	"context"
	"errors"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowtls"
	"github.com/metacubex/mihomo/transport/tlsmirror"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
)

type TLSConfig struct {
	Host                 string
	SkipCertVerify       bool
	NameCertVerify       string
	CAFile               string
	FingerPrint          string
	Certificate          string
	PrivateKey           string
	ClientFingerprint    string
	NextProtos           []string
	ECH                  *ech.Config
	ShadowTLS            *shadowtls.Config
	Restls               *restls.Config
	JLS                  *jls.Config
	Reality              *tlsC.RealityConfig
	TLSMirror            *tlsmirror.Config
	TLSMirrorDialer      tlsmirror.EnrollmentDialer
	ClientSessionCache   tls.ClientSessionCache
	UClientSessionCache  utls.ClientSessionCache
	DisableRenegotiation bool
}

func (cfg *TLSConfig) ToStdConfig() (*tls.Config, error) {
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.SkipCertVerify,
			NextProtos:         cfg.NextProtos,
			ClientSessionCache: cfg.ClientSessionCache,
		},
		Fingerprint:    cfg.FingerPrint,
		NameCertVerify: cfg.NameCertVerify,
		Certificate:    cfg.Certificate,
		PrivateKey:     cfg.PrivateKey,
	})
	if err != nil {
		return nil, err
	}
	if cfg.CAFile != "" {
		tlsConfig.RootCAs, err = ca.LoadCertificates(cfg.CAFile)
		if err != nil {
			return nil, err
		}
	}
	return tlsConfig, nil
}

func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	if cfg.ShadowTLS != nil {
		alpn := cfg.NextProtos
		if alpn == nil {
			alpn = shadowtls.DefaultALPN
		}
		return shadowtls.NewShadowTLS(ctx, conn, &shadowtls.ShadowTLSOption{
			Password:          cfg.ShadowTLS.Password,
			Host:              cfg.Host,
			Fingerprint:       cfg.FingerPrint,
			Certificate:       cfg.Certificate,
			PrivateKey:        cfg.PrivateKey,
			ClientFingerprint: cfg.ClientFingerprint,
			SkipCertVerify:    cfg.SkipCertVerify,
			NameCertVerify:    cfg.NameCertVerify,
			Version:           cfg.ShadowTLS.Version,
			ALPN:              alpn,
		})
	}
	if cfg.Restls != nil {
		restlsConfig := cfg.Restls.Clone()
		restlsConfig.ServerName = cfg.Host
		restlsConfig.NextProtos = cfg.NextProtos
		restlsConfig.InsecureSkipVerify = cfg.SkipCertVerify
		if cfg.FingerPrint != "" {
			if err := restls.SetFingerprint(restlsConfig, cfg.FingerPrint, cfg.NameCertVerify); err != nil {
				return nil, err
			}
		} else if cfg.NameCertVerify != "" {
			restls.SetNameCertVerify(restlsConfig, cfg.NameCertVerify)
		}
		return restls.NewRestls(ctx, conn, restlsConfig)
	}
	if cfg.JLS != nil {
		return jls.NewClient(ctx, conn, &jls.ClientConfig{
			Config:            *cfg.JLS,
			ServerName:        cfg.Host,
			ALPN:              cfg.NextProtos,
			ClientFingerprint: cfg.ClientFingerprint,
		})
	}
	if cfg.TLSMirror != nil {
		return tlsmirror.Dial(ctx, conn, tlsmirror.ClientConfig{
			Config:             *cfg.TLSMirror,
			ServerName:         cfg.Host,
			SkipCertVerify:     cfg.SkipCertVerify,
			NameCertVerify:     cfg.NameCertVerify,
			ALPN:               cfg.NextProtos,
			Fingerprint:        cfg.FingerPrint,
			Certificate:        cfg.Certificate,
			PrivateKey:         cfg.PrivateKey,
			ClientFingerprint:  cfg.ClientFingerprint,
			ForwardAddressHint: cfg.Host,
			ECH:                cfg.ECH,
			EnrollmentDialer:   cfg.TLSMirrorDialer,
		})
	}

	tlsConfig, err := cfg.ToStdConfig()
	if err != nil {
		return nil, err
	}

	if clientFingerprint, ok := tlsC.GetFingerprint(cfg.ClientFingerprint); ok {
		if cfg.Reality != nil {
			return tlsC.GetRealityConn(ctx, conn, clientFingerprint, tlsConfig.ServerName, cfg.Reality)
		}
		tlsConfig := tlsC.UConfig(tlsConfig)
		tlsConfig.ClientSessionCache = cfg.UClientSessionCache
		err = cfg.ECH.ClientHandleUTLS(ctx, tlsConfig)
		if err != nil {
			return nil, err
		}
		tlsConn := tlsC.UClient(conn, tlsConfig, clientFingerprint)
		if cfg.DisableRenegotiation {
			if err = tlsConn.BuildHandshakeState(); err != nil {
				return nil, err
			}
			for _, extension := range tlsConn.Extensions {
				if renegotiation, ok := extension.(*utls.RenegotiationInfoExtension); ok {
					renegotiation.Renegotiation = utls.RenegotiateNever
				}
			}
		}
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}
		return tlsConn, nil
	}
	if cfg.Reality != nil {
		return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
	}

	err = cfg.ECH.ClientHandle(ctx, tlsConfig)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, tlsConfig)

	err = tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}
