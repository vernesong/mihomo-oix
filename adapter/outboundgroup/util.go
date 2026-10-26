package outboundgroup

import (
	"context"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type ProxyGroup interface {
	C.ProxyAdapter

	Providers() []P.ProxyProvider
	Proxies() []C.Proxy
	Now() string
	Touch()

	Hidden() bool
	Icon() string

	URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16], timeout time.Duration) (mp map[string]uint16, err error)
}

var (
	_ ProxyGroup = (*Fallback)(nil)
	_ ProxyGroup = (*LoadBalance)(nil)
	_ ProxyGroup = (*URLTest)(nil)
	_ ProxyGroup = (*Selector)(nil)
	_ ProxyGroup = (*Smart)(nil)
)

type SelectAble interface {
	Set(string) error
	ForceSet(name string)
}

var (
	_ SelectAble = (*Fallback)(nil)
	_ SelectAble = (*URLTest)(nil)
	_ SelectAble = (*Selector)(nil)
	_ SelectAble = (*Smart)(nil)
)
