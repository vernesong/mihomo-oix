package adapter

import (
	"testing"
	"time"
)

func TestDurationToDelay(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     uint16
	}{
		{name: "zero", duration: 0, want: 1},
		{name: "sub-millisecond", duration: time.Microsecond, want: 1},
		{name: "one millisecond", duration: time.Millisecond, want: 1},
		{name: "whole milliseconds", duration: 42 * time.Millisecond, want: 42},
		{name: "fractional milliseconds", duration: 42*time.Millisecond + 999*time.Microsecond, want: 42},
		{name: "saturated", duration: 70 * time.Second, want: ^uint16(0)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := durationToDelay(test.duration); got != test.want {
				t.Fatalf("durationToDelay(%s) = %d, want %d", test.duration, got, test.want)
			}
		})
	}
}
