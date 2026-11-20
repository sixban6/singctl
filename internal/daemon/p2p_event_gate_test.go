package daemon

import (
	"testing"
	"time"
)

func TestP2PEventGate_ThrottleDirectOKOnly(t *testing.T) {
	gate := &p2pEventGate{}
	base := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	msgA := "节点 router-a 瞬时直连完成 (850ms 内关闭 WAN 窗口)"
	msgB := "节点 router-b 瞬时直连完成 (420ms 内关闭 WAN 窗口)"

	if !gate.shouldAppendRuntimeEvent("TS_P2P_DIRECT_OK", msgA, base) {
		t.Fatal("first TS_P2P_DIRECT_OK for router-a should be emitted")
	}
	if gate.shouldAppendRuntimeEvent("TS_P2P_DIRECT_OK", msgA, base.Add(31*time.Minute)) {
		t.Fatal("second TS_P2P_DIRECT_OK for router-a within 2h should be throttled")
	}
	if !gate.shouldAppendRuntimeEvent("TS_P2P_DIRECT_OK", msgB, base.Add(31*time.Minute)) {
		t.Fatal("TS_P2P_DIRECT_OK for router-b should be tracked independently")
	}
	if !gate.shouldAppendRuntimeEvent("TS_P2P_DIRECT_OK", msgA, base.Add(2*time.Hour)) {
		t.Fatal("TS_P2P_DIRECT_OK for router-a after 2h should be emitted again")
	}

	// Non-DIRECT_OK events must never be suppressed
	for i := range 5 {
		if !gate.shouldAppendRuntimeEvent("TS_P2P_COOLDOWN", "节点 router-a 连续 2 次打洞未成", base.Add(time.Duration(i)*time.Minute)) {
			t.Fatal("TS_P2P_COOLDOWN should never be throttled")
		}
		if !gate.shouldAppendRuntimeEvent("TS_P2P_POKE", "节点 router-a 手动测试", base.Add(time.Duration(i)*time.Minute)) {
			t.Fatal("TS_P2P_POKE should never be throttled")
		}
	}
}
