package provider

import "testing"

func TestHealthCheckProxiesCanChangeDuringACheck(t *testing.T) {
	hc := NewHealthCheck(nil, "", 0, 0, false, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			hc.check()
		}
	}()
	for range 1000 {
		hc.setProxies(nil)
	}
	<-done
}
