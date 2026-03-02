package test

import (
	"singctl/internal/util/netinfo"
	"testing"
)

func TestBandwidthRunSpeedTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping bandwidth test in short mode")
	}

	// This integration test will actually run the speed test against external servers
	// so it might take a while.
	err := netinfo.RunSpeedTest()
	if err != nil {
		t.Fatalf("RunSpeedTest failed: %v", err)
	}
}
