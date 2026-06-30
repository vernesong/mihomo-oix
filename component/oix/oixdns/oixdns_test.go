package oixdns

import "testing"

func TestShouldObfuscateNormalizesConfiguredDomain(t *testing.T) {
	oldNodesDomains := NodesDomains
	NodesDomains = "Example.COM."
	t.Cleanup(func() {
		NodesDomains = oldNodesDomains
	})

	if !ShouldObfuscate("node.example.com.") {
		t.Fatal("expected matching domain despite configured case and trailing dot")
	}
}

func TestClearEnsured(t *testing.T) {
	SetEnsured()
	ClearEnsured()

	if IsEnsured() {
		t.Fatal("expected ClearEnsured to disable OIX DNS routing")
	}
}
