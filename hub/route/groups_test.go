package route

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func newGroupDelayRequest(t *testing.T, name, testURL string, count, timeout int) (*http.Request, []C.Proxy) {
	t.Helper()
	nodes := make([]C.Proxy, count)
	for i := range nodes {
		nodes[i] = adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: fmt.Sprintf("%s-%d", name, i)}))
	}
	group, err := outboundgroup.NewSelector(outboundgroup.GroupCommonOption{Name: name}, outboundgroup.SelectorOption{}, nodes[0], []P.ProxyProvider{&staticProxyProvider{proxies: nodes}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/group/%s/delay?url=%s&timeout=%d&expected=204", name, url.QueryEscape(testURL), timeout), nil)
	return req.WithContext(context.WithValue(req.Context(), CtxKeyProxy, adapter.NewProxy(group))), nodes
}

func TestGroupDelaySharesConcurrencyAndGivesQueuedNodesFullTimeout(t *testing.T) {
	var active, peak atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		select {
		case <-time.After(250 * time.Millisecond):
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()

	const nodesPerGroup, probeTimeout = 25, 1000
	var wg sync.WaitGroup
	start := time.Now()
	for _, name := range []string{"one", "two"} {
		req, nodes := newGroupDelayRequest(t, name, server.URL, nodesPerGroup, probeTimeout)
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := httptest.NewRecorder()
			getGroupDelay(res, req)
			if res.Code != http.StatusOK {
				t.Errorf("group response = %d: %s", res.Code, res.Body.String())
				return
			}
			var delays map[string]uint16
			if err := json.Unmarshal(res.Body.Bytes(), &delays); err != nil {
				t.Error(err)
				return
			}
			if len(delays) != nodesPerGroup {
				t.Errorf("completed %d nodes, want %d (queueing must not consume probe timeout)", len(delays), nodesPerGroup)
			}
			for _, node := range nodes {
				delay := delays[node.Name()]
				if delay == 0 || delay >= probeTimeout {
					t.Errorf("node delay = %d, must contain only the admitted probe duration", delay)
				}
				if !node.AliveForTestUrl(server.URL) {
					t.Errorf("successfully probed node marked dead: %s", node.Name())
				}
			}
		}()
	}
	wg.Wait()
	t.Logf("50 nodes across 2 groups: peak=%d, elapsed=%s", peak.Load(), time.Since(start))
	if got := peak.Load(); got > 10 {
		t.Errorf("peak concurrent probes = %d, want at most 10 across both groups", got)
	}
}

func TestGroupDelayCancellationLeavesQueuedNodesUntouched(t *testing.T) {
	started := make(chan struct{}, 30)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	req, nodes := newGroupDelayRequest(t, "cancel", server.URL, 30, 5000)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	done := make(chan struct{})
	res := httptest.NewRecorder()
	go func() {
		getGroupDelay(res, req.WithContext(ctx))
		close(done)
	}()
	for i := 0; i < 10; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("initial probes did not start")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled request did not stop")
	}
	if res.Code != http.StatusGatewayTimeout {
		t.Fatalf("canceled request status = %d", res.Code)
	}
	tested := 0
	for _, node := range nodes {
		if len(node.DelayHistory()) != 0 {
			tested++
		}
	}
	if tested != 10 {
		t.Fatalf("%d nodes received history entries; only 10 admitted nodes should have been tested", tested)
	}
	// A later request must still acquire every slot after cancellation.
	readyStarted, release := make(chan struct{}, 10), make(chan struct{})
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readyStarted <- struct{}{}
		select {
		case <-release:
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	}))
	defer ready.Close()
	next, _ := newGroupDelayRequest(t, "next", ready.URL, 12, 5000)
	nextCtx, nextCancel := context.WithTimeout(next.Context(), 3*time.Second)
	defer nextCancel()
	nextRes := httptest.NewRecorder()
	nextDone := make(chan struct{})
	go func() {
		getGroupDelay(nextRes, next.WithContext(nextCtx))
		close(nextDone)
	}()
	for i := 0; i < 10; i++ {
		select {
		case <-readyStarted:
		case <-nextCtx.Done():
			t.Fatal("cancellation leaked probe slots")
		}
	}
	close(release)
	select {
	case <-nextDone:
	case <-nextCtx.Done():
		t.Fatal("request after cancellation did not complete")
	}
	if nextRes.Code != http.StatusOK {
		t.Fatalf("request after cancellation = %d: %s", nextRes.Code, nextRes.Body.String())
	}
}

func TestGroupDelayKeepsSuccessfulResultsWhenOtherNodesTimeOut(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	req, nodes := newGroupDelayRequest(t, "partial", server.URL, 18, 100)
	res := httptest.NewRecorder()
	getGroupDelay(res, req)
	var delays map[string]uint16
	if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &delays) != nil || len(delays) != 2 {
		t.Fatalf("partial response = %d: %s", res.Code, res.Body.String())
	}
	for _, node := range nodes {
		if len(node.DelayHistory()) != 1 {
			t.Fatalf("node %s was skipped after earlier timeouts", node.Name())
		}
	}
	failedReq, _ := newGroupDelayRequest(t, "failed", server.URL, 12, 100)
	failedRes := httptest.NewRecorder()
	getGroupDelay(failedRes, failedReq)
	if failedRes.Code != http.StatusGatewayTimeout {
		t.Fatalf("all failed response = %d: %s", failedRes.Code, failedRes.Body.String())
	}
}

func TestGroupDelayPreservesConfiguredURLAndClearsAutomaticGroupPin(t *testing.T) {
	groupName, nodeName, groupProxy, _ := setupURLTestRoute(t)
	fixProxySelection(t, proxyRouter(), groupName, nodeName)
	// URLTest groups must keep using their configured health-check URL, even
	// when the caller supplies a different (unreachable) URL.
	path := "/" + url.PathEscape(groupName) + "/delay?url=http%3A%2F%2F127.0.0.1%3A0&timeout=1000&expected=204"
	res := httptest.NewRecorder()
	groupRouter().ServeHTTP(res, httptest.NewRequest(http.MethodGet, path, nil))
	if res.Code != http.StatusOK {
		t.Fatalf("automatic group delay = %d: %s", res.Code, res.Body.String())
	}
	if fixedSelection(t, groupProxy) != "" || cachedSelection(t, groupName) != "" {
		t.Fatal("group delay did not clear the manual pin")
	}
}

func TestGroupDelayRejectsNonpositiveTimeoutWithoutChangingHealth(t *testing.T) {
	for _, timeout := range []int{0, -1} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			req, nodes := newGroupDelayRequest(t, "invalid", "http://127.0.0.1:0", 2, timeout)
			res := httptest.NewRecorder()
			getGroupDelay(res, req)
			if res.Code != http.StatusBadRequest {
				t.Errorf("invalid timeout status = %d, want 400", res.Code)
			}
			for _, node := range nodes {
				if len(node.DelayHistory()) != 0 || !node.AliveForTestUrl("http://127.0.0.1:0") {
					t.Error("invalid timeout changed node health")
				}
			}
		})
	}
}
