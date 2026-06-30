// Package oixdns provides DNS obfuscation utilities for OIX-managed domains.
// Placed in a sub-package to avoid import cycles between oix and resolver/dialer.
package oixdns

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	DNSPrivateKey string
	NodesDomains  string
	DNSAddr       string
)

var Ensured int32

func SetEnsured() {
	atomic.StoreInt32(&Ensured, 1)
}

func ClearEnsured() {
	atomic.StoreInt32(&Ensured, 0)
}

func IsEnsured() bool {
	return atomic.LoadInt32(&Ensured) == 1
}

var (
	base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	cloudIPs       sync.Map

	privKeyOnce sync.Once
	privKey     ed25519.PrivateKey
)

func loadPrivKey() ed25519.PrivateKey {
	privKeyOnce.Do(func() {
		if DNSPrivateKey == "" {
			return
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(DNSPrivateKey))
		if err != nil || len(seed) != ed25519.SeedSize {
			return
		}
		privKey = ed25519.NewKeyFromSeed(seed)
	})
	return privKey
}

func MarkCloudIP(ip string) {
	cloudIPs.Store(ip, true)
}

func isCloudIP(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return false
	}
	_, ok := cloudIPs.Load(host)
	return ok
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func nodesDomain() string {
	return normalizeDomain(NodesDomains)
}

func ShouldObfuscate(domain string) bool {
	nodes := nodesDomain()
	if nodes == "" {
		return false
	}
	d := normalizeDomain(domain)
	if d == nodes {
		return true
	}
	return strings.HasSuffix(d, "."+nodes)
}

func Obfuscate(domain string) string {
	basename := normalizeDomain(domain)
	pk := loadPrivKey()
	if pk == nil {
		return domain
	}
	window := time.Now().Unix() / 300
	message := []byte(basename + "|" + strconv.FormatInt(window, 10))
	sig := ed25519.Sign(pk, message)
	half := ed25519.SignatureSize / 2
	p1 := strings.ToLower(base32Encoding.EncodeToString(sig[:half]))
	p2 := strings.ToLower(base32Encoding.EncodeToString(sig[half:]))
	return p1 + "." + p2 + "." + basename
}

func MaskDomain(domain string) string {
	nodes := nodesDomain()
	if nodes == "" {
		return "***"
	}
	d := normalizeDomain(domain)
	if d == nodes {
		return "***." + nodes
	}
	suffix := "." + nodes
	if strings.HasSuffix(d, suffix) {
		return "***" + suffix
	}
	return "***." + nodes
}

func ShouldMask(host string) bool {
	if ShouldObfuscate(host) {
		return true
	}
	return isCloudIP(host)
}

func Mask(host string) string {
	if ShouldObfuscate(host) {
		return MaskDomain(host)
	}
	if isCloudIP(host) {
		if _, port, err := net.SplitHostPort(host); err == nil {
			return "***.***.***.***:" + port
		}
		return "***.***.***.***"
	}
	return host
}
