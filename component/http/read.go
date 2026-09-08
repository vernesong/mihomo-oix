package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/listener/inner"
)

const MaxReadBytes int64 = 64 << 20

// StatusError deliberately omits URLs, credentials and untrusted response bodies.
type StatusError int

func (s StatusError) Error() string { return fmt.Sprintf("HTTP %d", int(s)) }
func IsAuthenticationError(err error) bool {
	var status StatusError
	return errors.As(err, &status) && (status == http.StatusUnauthorized || status == http.StatusForbidden)
}

// RedactError preserves transport causes without logging query tokens or userinfo.
func RedactError(err error) error {
	var u *url.Error
	if errors.As(err, &u) {
		return fmt.Errorf("HTTP %s: %w", u.Op, RedactError(u.Err))
	}
	return err
}

// RaceReads races complete, repeatable reads under one deadline. Validation runs
// serially, allowing callers to retain parsed objects without duplicating them.
// A received authentication refusal cancels every still-pending candidate.
func RaceReads[T any](parent context.Context, attempts []func(context.Context) (T, error), validate func(T) error, terminal ...func(error) bool) (T, error) {
	var zero T
	isTerminal := IsAuthenticationError
	if len(terminal) > 0 && terminal[0] != nil {
		isTerminal = terminal[0]
	}
	if err := context.Cause(parent); err != nil {
		return zero, err
	}
	if len(attempts) == 0 {
		return zero, errors.New("no read routes")
	}
	deadline, deadlineCancel := context.WithTimeout(parent, 90*time.Second)
	defer deadlineCancel()
	ctx, cancel := context.WithCancelCause(deadline)
	defer cancel(context.Canceled)
	type result struct {
		value T
		err   error
	}
	results := make(chan result, len(attempts))
	for _, attempt := range attempts {
		go func() {
			value, err := attempt(ctx)
			if isTerminal(err) {
				cancel(err)
			}
			results <- result{value, err}
		}()
	}
	var errs []error
	for range attempts {
		select {
		case <-ctx.Done():
			return zero, context.Cause(ctx)
		case r := <-results:
			if err := context.Cause(ctx); err != nil {
				return zero, err
			}
			if r.err == nil && validate != nil {
				r.err = validate(r.value)
			}
			if err := context.Cause(ctx); err != nil {
				return zero, err
			}
			if r.err == nil {
				return r.value, nil
			}
			if isTerminal(r.err) {
				cancel(r.err)
				return zero, r.err
			}
			errs = append(errs, RedactError(r.err))
		}
	}
	return zero, errors.Join(errs...)
}

// StripRedirectCredentials prevents bearer/basic tokens and signed query strings
// in Referer from crossing an origin boundary (including a different port).
func StripRedirectCredentials(header map[string][]string, target, initial *url.URL) {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	if strings.EqualFold(target.Scheme, initial.Scheme) && strings.EqualFold(target.Hostname(), initial.Hostname()) && port(target) == port(initial) {
		return
	}
	for key := range header {
		switch strings.ToLower(key) {
		case "authorization", "cookie", "proxy-authorization", "referer":
			delete(header, key)
		}
	}
}

type readResponse struct {
	response *http.Response
	data     []byte
}

// Get reads the configured route and explicit direct route concurrently. Only a
// complete successful body accepted by validate can win. With no configured
// tunnel/dialer, a single explicit direct read avoids duplicate requests.
func Get(ctx context.Context, address string, header map[string][]string, maxBytes int64, validate func(*http.Response, []byte) error, options ...Option) (*http.Response, []byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxReadBytes
	}
	if maxBytes > 512<<20 {
		return nil, nil, errors.New("read limit exceeds 512 MiB")
	}
	opt := option{}
	for _, apply := range options {
		apply(&opt)
	}
	isTerminal := IsAuthenticationError
	if parsed, err := url.Parse(address); err == nil && opt.publicRead && parsed.User == nil && parsed.RawQuery == "" {
		authenticated := false
		for key, values := range header {
			switch strings.ToLower(key) {
			case "authorization", "cookie", "proxy-authorization":
				authenticated = authenticated || strings.Join(values, "") != ""
			}
		}
		if !authenticated {
			isTerminal = func(err error) bool {
				var status StatusError
				return errors.As(err, &status) && status == http.StatusUnauthorized
			}
		}
	}
	direct := dialer.NewDialer(dialer.WithResolver(resolver.DirectHostResolver))
	routes := [][]Option{append(append([]Option{}, options...), WithDialer(direct))}
	if inner.GetTunnel() != nil || opt.dialer != nil {
		routes = append([][]Option{options}, routes...)
	}
	attempts := make([]func(context.Context) (readResponse, error), 0, len(routes))
	for _, route := range routes {
		attempts = append(attempts, func(ctx context.Context) (readResponse, error) {
			resp, err := HttpRequest(ctx, address, http.MethodGet, header, nil, route...)
			if err != nil {
				return readResponse{}, RedactError(err)
			}
			defer resp.Body.Close()
			result := readResponse{response: resp}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				if resp.StatusCode != http.StatusNotModified || http.Header(header).Get("If-None-Match") == "" {
					return result, StatusError(resp.StatusCode)
				}
			}
			if resp.ContentLength > maxBytes {
				return result, fmt.Errorf("response exceeds %d bytes", maxBytes)
			}
			result.data, err = io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
			if err != nil {
				return readResponse{}, RedactError(err)
			}
			if int64(len(result.data)) > maxBytes {
				return readResponse{}, fmt.Errorf("response exceeds %d bytes", maxBytes)
			}
			return result, nil
		})
	}
	winner, err := RaceReads(ctx, attempts, func(result readResponse) error {
		if validate != nil {
			return validate(result.response, result.data)
		}
		return nil
	}, isTerminal)
	if err != nil {
		return nil, nil, err
	}
	return winner.response, winner.data, nil
}
