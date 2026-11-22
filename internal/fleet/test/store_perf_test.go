// 文件职责：验证 Fleet Store 文件指纹缓存命中、外部修改自动失效与高并发读写竞态基准测试。
package fleet_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"singctl/internal/fleet"
)

func TestStore_List_CachesParsedYAMLAndInvalidatesOnWriteOrExternalEdit(t *testing.T) {
	tmpDir := t.TempDir()
	fleetPath := filepath.Join(tmpDir, "fleet.yaml")
	s := fleet.NewStore(fleetPath)

	for i := range 10 {
		if _, err := s.Upsert(fleet.UpsertInput{
			ID:       fmt.Sprintf("node-%02d", i),
			Name:     fmt.Sprintf("Edge %02d", i),
			Host:     fmt.Sprintf("198.51.100.%d", 10+i),
			User:     "root",
			Password: "test-password",
		}); err != nil {
			t.Fatalf("Upsert %d failed: %v", i, err)
		}
	}
	s.ResetDiskParseCount()

	for i := range 20 {
		nodes, err := s.List()
		if err != nil || len(nodes) != 10 {
			t.Fatalf("List iteration %d failed: len=%d err=%v", i, len(nodes), err)
		}
	}
	if parses := s.DiskParseCount(); parses > 1 {
		t.Fatalf("expected <=1 disk YAML parse across 20 cached List() calls, got %d", parses)
	}

	if _, err := s.UpdateProbeRuntimeState("node-01", func(n *fleet.Node) {
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
	s := fleet.NewStore(fleetPath)
	for i := range 8 {
		if _, err := s.Upsert(fleet.UpsertInput{
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
					_, _ = s.UpdateProbeRuntimeState(fmt.Sprintf("n%d", g), func(n *fleet.Node) {
						n.LatencyMs = 20 + j
						n.LastProbeAt = time.Now().Format(time.RFC3339)
					}, 10*time.Minute)
				}
				nodes, err := s.List()
				if err != nil || len(nodes) != 8 {
					t.Errorf("concurrent List failed: len=%d err=%v", len(nodes), err)
					return
				}
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
	s := fleet.NewStore(fleetPath)
	for i := range 50 {
		if _, err := s.Upsert(fleet.UpsertInput{
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
