package oix

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"unicode/utf8"
)

const rulesPath = "/api/v1/rules"
const saveRulesPath = "/api/v1/rules/save"
const maxEditableRuleBytes = 8192

var errRulesInput = errors.New("规则内容或版本无效，请重新读取面板规则")
var errRulesTooLarge = errors.New("account rules exceed the router editor limit")

type ruleState struct {
	CustomRules string `json:"custom_rules"`
	Revision    string `json:"revision"`
}

func (r *ruleState) encoded() string { return base64.StdEncoding.EncodeToString([]byte(r.CustomRules)) }

func readAccountRules(ctx context.Context, token string) (*ruleState, error) {
	data, err := accountRequest(ctx, rulesPath, token, nil)
	if err != nil {
		return nil, err
	}
	return parseRuleState(data)
}

func saveAccountRules(ctx context.Context, token string, encoded *string, revision string) (*ruleState, error) {
	if encoded == nil || len(*encoded) > base64.StdEncoding.EncodedLen(maxEditableRuleBytes) {
		return nil, errRulesInput
	}
	rules, err := base64.StdEncoding.Strict().DecodeString(*encoded)
	digest, digestErr := hex.DecodeString(revision)
	if err != nil || !utf8.Valid(rules) || len(rules) > maxEditableRuleBytes || digestErr != nil || len(digest) != sha256.Size {
		return nil, errRulesInput
	}
	data, err := accountRequest(ctx, saveRulesPath, token, url.Values{"custom_rules": {string(rules)}, "revision": {revision}})
	if err != nil {
		return nil, err
	}
	return parseRuleState(data)
}

func parseRuleState(data map[string]any) (*ruleState, error) {
	rules, rulesOK := data["custom_rules"].(string)
	revision, revisionOK := data["revision"].(string)
	if !rulesOK || !revisionOK || !utf8.ValidString(rules) {
		return nil, errRulesInput
	}
	hash := sha256.Sum256([]byte(rules))
	if revision != hex.EncodeToString(hash[:]) {
		return nil, errRulesInput
	}
	// Never truncate an account's shared rules into an editable draft.
	if len(rules) > maxEditableRuleBytes {
		return nil, errRulesTooLarge
	}
	return &ruleState{CustomRules: rules, Revision: revision}, nil
}
