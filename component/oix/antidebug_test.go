package oix

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPackageInitDoesNotExitOnInjectionEnv(t *testing.T) {
	if os.Getenv("OIX_INIT_HELPER") == "1" {
		return
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=TestPackageInitDoesNotExitOnInjectionEnv")
	cmd.Env = append(os.Environ(),
		"OIX_INIT_HELPER=1",
		"LD_PRELOAD=/tmp/oix-test-preload.so",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected OIX package import to be side-effect free under injection env, err=%v output=%s", err, output)
	}
}

func TestDecodeXORHexRejectsMalformedEncodedValue(t *testing.T) {
	oldErr := secretDecodeErr
	secretDecodeErr = nil
	t.Cleanup(func() {
		secretDecodeErr = oldErr
	})

	if got := decodeXORHex("not-hex", 0xA3); got != "" {
		t.Fatalf("expected malformed encoded value to decode to empty string, got %q", got)
	}
	if err := lastSecretDecodeError(); err == nil || !strings.Contains(err.Error(), "invalid xor hex") {
		t.Fatalf("expected malformed encoded value to be recorded, got %v", err)
	}
}
