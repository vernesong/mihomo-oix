// Package oixdns provides DNS obfuscation utilities for OIX-managed domains.
// Placed in a sub-package to avoid import cycles between oix and resolver/dialer.
package oixdns

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	DNSSecret    string
	NodesDomains string
	DNSAddr      string
)

var (
	base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	cloudIPs       sync.Map
)

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

func ShouldObfuscate(domain string) bool {
	if NodesDomains == "" {
		return false
	}
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if d == NodesDomains {
		return true
	}
	return strings.HasSuffix(d, "."+NodesDomains)
}

func Obfuscate(domain string) string {
	basename := strings.ToLower(strings.TrimSuffix(domain, "."))
	window := time.Now().Unix() / 300
	payload := basename + "|" + strconv.FormatInt(window, 10)

	mac := hmac.New(sha256.New, []byte(DNSSecret))
	mac.Write([]byte(payload))
	digest := mac.Sum(nil)[:10]

	token := strings.ToLower(base32Encoding.EncodeToString(digest))
	return token + "." + basename
}

func MaskDomain(domain string) string {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if d == NodesDomains {
		return "***." + NodesDomains
	}
	suffix := "." + NodesDomains
	if strings.HasSuffix(d, suffix) {
		return "***" + suffix
	}
	return "***." + NodesDomains
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
