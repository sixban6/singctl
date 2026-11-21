package fleet

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStore_List_CachesParsedYAMLAndInvalidatesOnWriteOrExternalEdit(t *testing.T) {
	tmpDir := t.TempDir()
	fleetPath := filepath.Join(tmpDir, "fleet.yaml")
	s := NewStore(fleetPath)

	for i := range 10 {
		if _, err := s.Upsert(UpsertInput{
			ID:       fmt.Sprintf("node-%02d", i),
			Name:     fmt.Sprintf("Edge %02d", i),
			Host:     fmt.Sprintf("198.51.100.%d", 10+i),
			User:     "root",
			Password: "test-password",
		}); err != nil {
			t.Fatalf("Upsert %d failed: %v", i, err)
		}
	}
	s.diskParseCount.Store(0)

	// 1. 连续 20 次 List(): 首轮触发/命中，0 次额外磁盘 YAML 反序列化
	for i := range 20 {
		nodes, err := s.List()
		if err != nil || len(nodes) != 10 {
			t.Fatalf("List iteration %d failed: len=%d err=%v", i, len(nodes), err)
		}
	}
	if parses := s.diskParseCount.Load(); parses > 1 {
		t.Fatalf("expected <=1 disk YAML parse across 20 cached List() calls, got %d", parses)
	}

	// 2. 内存探针节流覆盖（UpdateProbeRuntimeState）不触发磁盘 YAML 解析，且读取立刻反映最新 LatencyMs
	if _, err := s.UpdateProbeRuntimeState("node-01", func(n *Node) {
		n.LatencyMs = 77
		n.LastProbeAt = time.Now().Format(time.RFC3339)
	}, 10*time.Minute); err != nil {
		t.Fatalf("UpdateProbeRuntimeState failed: %v", err)
	}
	nodesAfterProbe, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var gotLatency int
	for _, n := range nodesAfterProbe {
		if n.ID == "node-01" {
			gotLatency = n.LatencyMs
		}
	}
	if gotLatency != 77 {
		t.Fatalf("expected in-memory latency overlay 77, got %d", gotLatency)
	}

	// 3. 外部直接修改 fleet.yaml -> 立刻感知 stat 指纹变更并重新解析
	extYAML := []byte("version: \"1\"\nnodes:\n  - id: ext-node\n    name: External Node\n    host: 203.0.113.99\n    port: 22\n    user: root\n    auth_type: password\n    password: test-password\n    enabled: true\n")
	if err := os.WriteFile(fleetPath, extYAML, 0600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(3 * time.Second)
	_ = os.Chtimes(fleetPath, future, future)

	extNodes, err := s.List()
	if err != nil || len(extNodes) != 1 || extNodes[0].ID != "ext-node" {
		t.Fatalf("expected external edit reload with ext-node, got %+v (err=%v)", extNodes, err)
	}

	// 4. Delete 与外部删除文件 -> 缓存同步清理
	if err := s.Delete("ext-node"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	afterDel, err := s.List()
	if err != nil || len(afterDel) != 0 {
		t.Fatalf("expected empty list after Delete, got %+v (err=%v)", afterDel, err)
	}
	if err := os.Remove(fleetPath); err != nil {
		t.Fatal(err)
	}
	afterRm, err := s.List()
	if err != nil || len(afterRm) != 0 {
		t.Fatalf("expected empty list after os.Remove, got %+v (err=%v)", afterRm, err)
	}
}

func TestStore_List_ConcurrentRaceWithUpdates(t *testing.T) {
	fleetPath := filepath.Join(t.TempDir(), "fleet.yaml")
	s := NewStore(fleetPath)
	for i := range 8 {
		if _, err := s.Upsert(UpsertInput{
			ID:       fmt.Sprintf("n%d", i),
			Name:     fmt.Sprintf("Node %d", i),
			Host:     fmt.Sprintf("198.51.100.%d", i+1),
			User:     "root",
			Password: "pw",
		}); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for j := range 25 {
				if j%5 == 0 {
					_, _ = s.UpdateProbeRuntimeState(fmt.Sprintf("n%d", g), func(n *Node) {
						n.LatencyMs = 20 + j
						n.LastProbeAt = time.Now().Format(time.RFC3339)
					}, 10*time.Minute)
				}
				nodes, err := s.List()
				if err != nil || len(nodes) != 8 {
					t.Errorf("concurrent List failed: len=%d err=%v", len(nodes), err)
					return
				}
				// 修改返回切片的内部字段不得污染共享缓存
				nodes[0].Name = "mutated-by-caller"
				if len(nodes[0].Protocols) > 0 {
					nodes[0].Protocols[0] = "tampered"
				}
			}
		})
	}
	wg.Wait()

	finalNodes, err := s.List()
	if err != nil || len(finalNodes) != 8 {
		t.Fatal(err)
	}
	if finalNodes[0].Name == "mutated-by-caller" {
		t.Fatal("caller mutation leaked into Store cache")
	}
}

func BenchmarkStore_List_50Nodes(b *testing.B) {
	fleetPath := filepath.Join(b.TempDir(), "fleet.yaml")
	s := NewStore(fleetPath)
	for i := range 50 {
		if _, err := s.Upsert(UpsertInput{
			ID:        fmt.Sprintf("node-%02d", i),
			Name:      fmt.Sprintf("Worker Node %02d", i),
			Host:      fmt.Sprintf("198.51.100.%d", i+10),
			User:      "root",
			Password:  "bench-password",
			Hy2Port:   10443 + i,
			VlessPort: 20443 + i,
		}); err != nil {
			b.Fatal(err)
		}
	}
	_, _ = s.List()

	b.ReportAllocs()
	for b.Loop() {
		nodes, err := s.List()
		if err != nil || len(nodes) != 50 {
			b.Fatalf("unexpected len=%d err=%v", len(nodes), err)
		}
	}
}
