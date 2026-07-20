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

type managedDNSConfig struct {
	domain string
	addr   string
}

var managedDNS atomic.Pointer[managedDNSConfig]

func ConfigureManagedDNS(domain, addr string) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	addr = strings.TrimSpace(addr)
	if domain == "" || addr == "" {
		return
	}
	managedDNS.Store(&managedDNSConfig{domain: domain, addr: addr})
}

func ResetManagedDNS() {
	managedDNS.Store(nil)
}

func ManagedDNSAddr() string {
	if config := managedDNS.Load(); config != nil {
		return config.addr
	}
	return DNSAddr
}

func ManagedNodesDomain() string {
	if config := managedDNS.Load(); config != nil {
		return config.domain
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(NodesDomains), "."))
}

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
	if key, ok := normalizeIPKey(ip); ok {
		cloudIPs.Store(key, true)
	}
}

// normalizeIPKey strips an optional port and returns the unmapped textual form
// of an IP so stored and looked-up keys always match (e.g. IPv4-in-IPv6).
func normalizeIPKey(host string) (string, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	return addr.Unmap().String(), true
}

func isCloudIP(host string) bool {
	key, ok := normalizeIPKey(host)
	if !ok {
		return false
	}
	_, ok = cloudIPs.Load(key)
	return ok
}

func ShouldObfuscate(domain string) bool {
	nodesDomain := ManagedNodesDomain()
	if nodesDomain == "" {
		return false
	}
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if d == nodesDomain {
		return true
	}
	return strings.HasSuffix(d, "."+nodesDomain)
}

func Obfuscate(domain string) string {
	basename := strings.ToLower(strings.TrimSuffix(domain, "."))
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
	nodesDomain := ManagedNodesDomain()
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if d == nodesDomain {
		return "***." + nodesDomain
	}
	suffix := "." + nodesDomain
	if strings.HasSuffix(d, suffix) {
		return "***" + suffix
	}
	return "***." + nodesDomain
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
