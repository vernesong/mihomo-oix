package logic_test

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	// https://github.com/golang/go/wiki/CodeReviewComments#import-dot
	. "github.com/metacubex/mihomo/rules/logic"

	"github.com/stretchr/testify/assert"
)

var ParseRule = rules.ParseRule

func TestAND(t *testing.T) {
	and, err := NewAND("((DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT", ParseRule)
	assert.Equal(t, nil, err)
	assert.Equal(t, "DIRECT", and.Adapter())
	m, _ := and.Match(&C.Metadata{
		Host:    "baidu.com",
		NetWork: C.TCP,
		DstPort: 20000,
	}, C.RuleMatchHelper{})
	assert.Equal(t, true, m)

	and, err = NewAND("(DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT", ParseRule)
	assert.NotEqual(t, nil, err)
	assert.Nil(t, and)

	and, err = NewAND("((AND,(DOMAIN,baidu.com),(NETWORK,TCP)),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT", ParseRule)
	assert.Equal(t, nil, err)
	assert.NotNil(t, and)
}

func TestNOT(t *testing.T) {
	not, err := NewNOT("((DST-PORT,6000-6500))", "REJECT", ParseRule)
	assert.Equal(t, nil, err)
	m, _ := not.Match(&C.Metadata{
		DstPort: 6100,
	}, C.RuleMatchHelper{})
	assert.Equal(t, false, m)

	_, err = NewNOT("(DST-PORT,5600-6666)", "DIRECT", ParseRule)
	assert.NotEqual(t, nil, err)

	_, err = NewNOT("DST-PORT,5600-6666", "DIRECT", ParseRule)
	assert.NotEqual(t, nil, err)

	_, err = NewNOT("((DST-PORT,5600-6666),(DOMAIN,baidu.com))", "DIRECT", ParseRule)
	assert.NotEqual(t, nil, err)

	_, err = NewNOT("(())", "DIRECT", ParseRule)
	assert.NotEqual(t, nil, err)
}

func TestOR(t *testing.T) {
	or, err := NewOR("((DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT", ParseRule)
	assert.Equal(t, nil, err)
	m, _ := or.Match(&C.Metadata{
		NetWork: C.TCP,
	}, C.RuleMatchHelper{})
	assert.Equal(t, true, m)
}
