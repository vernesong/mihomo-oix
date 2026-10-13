package tuic_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/metacubex/mihomo/transport/tuic"
	"github.com/metacubex/mihomo/transport/tuic/types"
)

func TestErrorNameCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name            string
		current, legacy error
		message         string
	}{
		{"client closed", types.ErrClientClosed, types.ClientClosed, "tuic: client closed"},
		{"types stream limit", types.ErrTooManyOpenStreams, types.TooManyOpenStreams, "tuic: too many open streams"},
		{"public stream limit", tuic.ErrTooManyOpenStreams, tuic.TooManyOpenStreams, "tuic: too many open streams"},
		{"cross-package stream limit", types.ErrTooManyOpenStreams, tuic.TooManyOpenStreams, "tuic: too many open streams"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.current != tc.legacy || tc.current.Error() != tc.message {
				t.Fatal("legacy sentinel identity or message changed")
			}
			if !errors.Is(fmt.Errorf("wrapped: %w", tc.current), tc.legacy) || !errors.Is(fmt.Errorf("wrapped: %w", tc.legacy), tc.current) {
				t.Fatal("legacy errors.Is matching changed")
			}
		})
	}
}
