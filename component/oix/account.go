package oix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	mihomoHttp "github.com/metacubex/mihomo/component/http"
)

// Account endpoints the panel serves to official clients. Unlike the managed
// config they are not signed; the client header decides which client a
// sign-in token belongs to.
const (
	loginPath               = "/api/v1/login"
	informationPath         = "/api/v1/information"
	rebindPath              = "/api/v1/token/rebind"
	maxAccountResponseBytes = 1 << 20
)

var (
	ErrRateLimited = errors.New("rate limited")
	ErrPanelServer = errors.New("panel server error")
)

// PanelError is a refusal the panel explained in its own words, already in
// the requested language, so callers can show Msg to the user as is.
type PanelError struct {
	Ret int
	Msg string
	err error
}

func (e *PanelError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return fmt.Sprintf("panel rejected the request (ret=%d)", e.Ret)
}

func (e *PanelError) Unwrap() error { return e.err }

type Account struct {
	Plan        string `json:"plan"`
	PlanTime    string `json:"plan_time"`
	PlanRank    int    `json:"plan_rank"`
	Used        string `json:"used"`
	Traffic     string `json:"traffic"`
	Unused      string `json:"unused"`
	TodayUsed   string `json:"today_used"`
	TokenClient string `json:"token_client"`
}

// LoginWithPassword signs in as the current client and returns its token,
// which the panel reuses for every device of the same client.
func LoginWithPassword(ctx context.Context, email, password string) (string, *Account, error) {
	form := url.Values{}
	form.Set("email", strings.TrimSpace(email))
	form.Set("passwd", password)
	form.Set("token_expire", "365")
	data, err := accountRequest(ctx, loginPath, "", form)
	if err != nil {
		return "", nil, err
	}
	token := normalizeToken(stringField(data, "token"))
	if token == "" {
		return "", nil, errors.New("sign-in response has no token")
	}
	return token, parseAccount(data), nil
}

func Information(ctx context.Context, token string) (*Account, error) {
	data, err := accountRequest(ctx, informationPath, normalizeToken(token), nil)
	if err != nil {
		return nil, err
	}
	return parseAccount(data), nil
}

// Rebind trades a sign-in token another official client obtained for this
// client's own one; the old token stays with its client.
func Rebind(ctx context.Context, token string) (string, error) {
	data, err := accountRequest(ctx, rebindPath, normalizeToken(token), nil)
	if err != nil {
		return "", err
	}
	rebound := normalizeToken(stringField(data, "token"))
	if rebound == "" {
		return "", errors.New("rebind response has no token")
	}
	return rebound, nil
}

// accountRequest tries the next API domain only when no panel answered;
// a panel's JSON verdict is final.
func accountRequest(ctx context.Context, path, token string, form url.Values) (map[string]any, error) {
	urls := apiBaseURLs()
	if len(urls) == 0 {
		return nil, ErrNoDomains
	}
	var lastErr error
	for _, baseURL := range urls {
		data, retry, err := accountRequestOnce(ctx, baseURL+path, token, form)
		if !retry {
			return data, err
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func accountRequestOnce(ctx context.Context, target, token string, form url.Values) (map[string]any, bool, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, body)
	if err != nil {
		return nil, false, fmt.Errorf("create request: %w", mihomoHttp.RedactError(err))
	}
	client, userAgent := currentClient()
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set(oixClientHeader, client)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "zh-CN")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := oixHTTPClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("server request: %w", mihomoHttp.RedactError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusInternalServerError {
		return nil, true, fmt.Errorf("%w: HTTP %d", ErrPanelServer, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, false, &PanelError{Ret: resp.StatusCode, err: ErrRateLimited}
		}
		return nil, false, oixStatusError(resp.StatusCode)
	}

	var envelope map[string]any
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxAccountResponseBytes))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, false, fmt.Errorf("decode response: %w", err)
	}
	ret, ok := intField(envelope, "ret")
	if !ok {
		return nil, false, errors.New("response has no ret")
	}
	data, _ := envelope["data"].(map[string]any)
	if ret == http.StatusOK {
		if data == nil {
			data = map[string]any{}
		}
		return data, false, nil
	}
	return nil, false, panelError(ret, stringField(envelope, "msg"), envelope, data)
}

func panelError(ret int, msg string, envelope, data map[string]any) error {
	retryAfter, _ := intField(envelope, "retry_after")
	if retryAfter == 0 && data != nil {
		retryAfter, _ = intField(data, "retry_after")
	}
	switch {
	case ret == http.StatusTooManyRequests || (ret == http.StatusForbidden && retryAfter > 0):
		return &PanelError{Ret: ret, Msg: msg, err: ErrRateLimited}
	case ret == http.StatusUnauthorized || ret == http.StatusForbidden:
		return &PanelError{Ret: ret, Msg: msg, err: ErrAuthFailed}
	case ret >= http.StatusInternalServerError:
		return fmt.Errorf("%w (ret=%d): %s", ErrPanelServer, ret, msg)
	default:
		return &PanelError{Ret: ret, Msg: msg}
	}
}

func parseAccount(data map[string]any) *Account {
	rank, _ := intField(data, "plan_rank")
	return &Account{
		Plan:        stringField(data, "plan"),
		PlanTime:    stringField(data, "plan_time"),
		PlanRank:    rank,
		Used:        stringField(data, "used"),
		Traffic:     stringField(data, "traffic"),
		Unused:      stringField(data, "unused"),
		TodayUsed:   stringField(data, "today_used"),
		TokenClient: stringField(data, "token_client"),
	}
}

// The panel sends numbers either as JSON numbers or as numeric strings.
func stringField(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func intField(m map[string]any, key string) (int, bool) {
	value := stringField(m, key)
	if value == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(value); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		return int(f), true
	}
	return 0, false
}
