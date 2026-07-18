package main

import (
	"os"
	"strings"
	"testing"
)

func TestLegacySubcommandClassification(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantName string
		wantRest []string
		wantOK   bool
	}{
		{
			name:     "convert ruleset",
			args:     []string{"mihomo", "convert-ruleset", "domain", "mrs", "in.txt", "out.mrs"},
			wantName: "convert-ruleset",
			wantRest: []string{"domain", "mrs", "in.txt", "out.mrs"},
			wantOK:   true,
		},
		{
			name:     "generate",
			args:     []string{"mihomo", "generate", "uuid"},
			wantName: "generate",
			wantRest: []string{"uuid"},
			wantOK:   true,
		},
		{
			name:     "age",
			args:     []string{"mihomo", "age", "keygen"},
			wantName: "age",
			wantRest: []string{"keygen"},
			wantOK:   true,
		},
		{
			name:   "main flags",
			args:   []string{"mihomo", "-v"},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotRest, gotOK := legacySubcommand(tt.args)
			if gotOK != tt.wantOK {
				t.Fatalf("legacySubcommand ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotName != tt.wantName {
				t.Fatalf("legacySubcommand name = %q, want %q", gotName, tt.wantName)
			}
			if strings.Join(gotRest, "\x00") != strings.Join(tt.wantRest, "\x00") {
				t.Fatalf("legacySubcommand rest = %#v, want %#v", gotRest, tt.wantRest)
			}
		})
	}
}

func TestBuildWorkflowFailsFastForRequiredOIXSecrets(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/build.yml")
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ReplaceAll(string(data), "\r\n", "\n")
	required := []string{
		"OIX_APP_SECRET",
		"OIX_DNS_PRIVATE_KEY",
		"OIX_DOMAINS",
		"OIX_DNS_ADDR",
		"OIX_API_DOMAINS",
		"OIX_PROFILE_KEY",
	}
	if !strings.Contains(body, "required=(") {
		t.Fatal("workflow does not declare required OIX secrets")
	}
	for _, name := range required {
		if !strings.Contains(body, "\n          "+name+"\n") {
			t.Fatalf("workflow required secret list is missing %s", name)
		}
	}
	for _, snippet := range []string{
		"::error title=Missing OIX secret::${name} is required for OIX builds",
		"missing=1",
		"if [ \"$missing\" -ne 0 ]; then",
		"exit 1",
	} {
		if !strings.Contains(body, snippet) {
			t.Fatalf("workflow missing fail-fast snippet %q", snippet)
		}
	}
}
