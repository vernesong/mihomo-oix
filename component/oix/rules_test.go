package oix

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func rulePayload(text string) map[string]any {
	sum := sha256.Sum256([]byte(text))
	return map[string]any{"custom_rules": text, "revision": hex.EncodeToString(sum[:])}
}

func TestRulesCLIReadSaveClearAndConflict(t *testing.T) {
	current := "DOMAIN,example.com,DIRECT\n# 中文"
	setupPanelTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer rules-token" || r.Header.Get("X-oixCloud-Client") != "oixclash" {
			t.Errorf("wrong method or authentication")
		}
		if r.URL.Path == saveRulesPath {
			if r.FormValue("revision") != rulePayload(current)["revision"] {
				writePanelJSON(w, map[string]any{"ret": 409, "msg": "规则已更新"})
				return
			}
			current = strings.TrimSpace(r.FormValue("custom_rules"))
		} else if r.URL.Path != rulesPath {
			t.Errorf("path = %s", r.URL.Path)
		}
		writePanelJSON(w, map[string]any{"ret": 200, "data": rulePayload(current)})
	}))
	t.Setenv("OIX_TOKEN", "rules-token")
	status, out := runCLI(t, "rules", map[string]string{})
	if status != exitOK || out.Rules == nil || out.Rules.CustomRules != current {
		t.Fatalf("read = %d %+v", status, out)
	}
	revision := out.Rules.Revision
	encoded := base64.StdEncoding.EncodeToString([]byte("DOMAIN,example.com,策略组\n"))
	status, out = runCLI(t, "save-rules", map[string]string{"rules_base64": encoded, "revision": revision})
	if status != exitOK || out.Rules == nil || out.Rules.CustomRules != "DOMAIN,example.com,策略组" {
		t.Fatalf("save = %d %+v", status, out)
	}
	newRevision := out.Rules.Revision
	status, _ = runCLI(t, "save-rules", map[string]string{"rules_base64": "", "revision": revision})
	if status != exitRejected || current == "" {
		t.Fatal("stale revision overwrote rules")
	}
	status, out = runCLI(t, "save-rules", map[string]string{"rules_base64": "", "revision": newRevision})
	if status != exitOK || out.Rules == nil || current != "" {
		t.Fatal("clear failed")
	}
	var lines strings.Builder
	writeLines(&lines, out)
	if !strings.Contains(lines.String(), "rules_base64=\nrevision=") {
		t.Fatalf("empty rules missing from shell output: %s", lines.String())
	}
}

func TestRulesRejectBadInputBeforeRequest(t *testing.T) {
	setupPanelTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("invalid input reached panel") }))
	t.Setenv("OIX_TOKEN", "rules-token")
	revision := rulePayload("")["revision"].(string)
	for _, input := range []map[string]string{
		{"revision": revision}, {"revision": revision, "rules_base64": "!"},
		{"revision": revision, "rules_base64": base64.StdEncoding.EncodeToString([]byte{255})},
		{"revision": "bad", "rules_base64": ""},
		{"revision": revision, "rules_base64": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 8193)))},
	} {
		status, _ := runCLI(t, "save-rules", input)
		if status == exitOK {
			t.Fatal("accepted invalid request")
		}
	}
}

func TestRulesNeverTruncateOrAcceptIncompleteResponse(t *testing.T) {
	if _, err := parseRuleState(rulePayload(strings.Repeat("中", 3000))); !errors.Is(err, errRulesTooLarge) {
		t.Fatalf("large response: %v", err)
	}
	for _, data := range []map[string]any{{}, {"custom_rules": "x", "revision": "bad"}, {"custom_rules": 42, "revision": "bad"}} {
		if _, err := parseRuleState(data); err == nil {
			t.Fatal("accepted invalid response")
		}
	}
	setupPanelTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writePanelJSON(w, map[string]any{"ret": 401, "msg": "token invalid"})
	}))
	if _, err := readAccountRules(context.Background(), "bad"); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("auth = %v", err)
	}
}
