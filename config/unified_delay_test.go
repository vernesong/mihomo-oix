package config

import "testing"

func TestUnifiedDelayDefaultsToTrue(t *testing.T) {
	if !DefaultRawConfig().UnifiedDelay {
		t.Fatal("unified-delay default = false, want true")
	}
}

func TestUnifiedDelayCanBeDisabled(t *testing.T) {
	config, err := UnmarshalRawConfig([]byte("unified-delay: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if config.UnifiedDelay {
		t.Fatal("unified-delay = true, want explicit false")
	}
}
