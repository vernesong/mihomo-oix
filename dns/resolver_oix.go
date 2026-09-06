package dns

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/oix/oixdns"

	D "github.com/miekg/dns"
)

// restoreoixQuestion keeps signing labels confined to the managed DNS exchange.
// Callers and caches continue to use the original question and record owners.
func restoreoixQuestion(msg *D.Msg, signedName string, question D.Question) {
	msg.Question = []D.Question{question}
	for _, records := range [][]D.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, record := range records {
			if strings.EqualFold(record.Header().Name, signedName) {
				record.Header().Name = question.Name
			}
		}
	}
}

// markCloudIPsFromMsg extracts IPs from a DNS response and registers them as cloud-nodes IPs.
func markCloudIPsFromMsg(msg *D.Msg) {
	for _, ip := range msgToIP(msg) {
		oixdns.MarkCloudIP(ip.String())
	}
}

func putoixMsgToCache(c dnsCache, q D.Question, msg *D.Msg) {
	if msg.Rcode != D.RcodeSuccess || len(msg.Answer) == 0 {
		return
	}
	putMsgToCache(c, q, msg)
}

const oixTCPHedgeDelay = 250 * time.Millisecond

// oixDNSClient queries over UDP first and hedges with TCP when UDP is slow.
type oixDNSClient struct {
	udp dnsClient
	tcp dnsClient
}

var oixClientCache struct {
	sync.Mutex
	addr   string
	client dnsClient
}

func oixSharedClient() dnsClient {
	addr := oixdns.ManagedDNSAddr()
	if addr == "" {
		return nil
	}
	oixClientCache.Lock()
	defer oixClientCache.Unlock()
	if oixClientCache.addr != addr {
		oixClientCache.addr = addr
		oixClientCache.client = &oixDNSClient{
			udp: newClient(addr, nil, "udp", nil, nil, ""),
			tcp: newClient(addr, nil, "tcp", nil, nil, ""),
		}
	}
	return oixClientCache.client
}

func (c *oixDNSClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type exchangeResult struct {
		msg *D.Msg
		err error
	}
	results := make(chan exchangeResult, 2)
	exchange := func(client dnsClient, request *D.Msg) {
		msg, err := client.ExchangeContext(ctx, request)
		if err == nil && msg == nil {
			err = errors.New("empty DNS response")
		}
		results <- exchangeResult{msg: msg, err: err}
	}

	udpRequest := m.Copy()
	tcpRequest := m.Copy()
	pending := 1
	tcpStarted := false
	go exchange(c.udp, udpRequest)
	timer := time.NewTimer(oixTCPHedgeDelay)
	defer timer.Stop()
	timerC := timer.C
	startTCP := func() {
		if tcpStarted {
			return
		}
		tcpStarted = true
		pending++
		go exchange(c.tcp, tcpRequest)
	}

	var errs []error
	for pending > 0 {
		select {
		case <-ctx.Done():
			return nil, errors.Join(append(errs, ctx.Err())...)
		case <-timerC:
			timerC = nil
			startTCP()
		case result := <-results:
			pending--
			if result.err == nil {
				return result.msg, nil
			}
			errs = append(errs, result.err)
			if !tcpStarted {
				timer.Stop()
				timerC = nil
				startTCP()
			}
		}
	}
	return nil, errors.Join(errs...)
}

func (c *oixDNSClient) Address() string { return c.udp.Address() }

func (c *oixDNSClient) ResetConnection() {
	c.udp.ResetConnection()
	c.tcp.ResetConnection()
}
