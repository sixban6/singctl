package fwtx_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"singctl/internal/platform/fwtx"
)

type recordedCall struct {
	Stdin string
	Name  string
	Args  []string
}

type mockRunner struct {
	calls []recordedCall
	fn    func(stdin, name string, args ...string) ([]byte, error)
}

func (m *mockRunner) RunStdin(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, recordedCall{
		Stdin: stdin,
		Name:  name,
		Args:  append([]string(nil), args...),
	})
	if m.fn != nil {
		return m.fn(stdin, name, args...)
	}
	return nil, nil
}

func TestWrapAtomicNFTTable(t *testing.T) {
	sample := "#!/usr/sbin/nft -f\ntable inet security {\n    chain input {\n        type filter hook input priority 0; policy accept;\n    }\n}\n"
	wrapped, err := fwtx.WrapAtomicNFTTable("inet", "security", sample)
	if err != nil {
		t.Fatalf("WrapAtomicNFTTable failed: %v", err)
	}
	idxAdd := strings.Index(wrapped, "add table inet security\n")
	idxFlush := strings.Index(wrapped, "flush table inet security\n")
	idxTable := strings.Index(wrapped, "table inet security {")
	if idxAdd < 0 || idxFlush < 0 || idxTable < 0 {
		t.Fatalf("missing atomic preamble in:\n%s", wrapped)
	}
	if !(idxAdd < idxFlush && idxFlush < idxTable) {
		t.Fatalf("invalid order: add=%d flush=%d table=%d\n%s", idxAdd, idxFlush, idxTable, wrapped)
	}

	// Idempotent when called a second time
	wrapped2, err := fwtx.WrapAtomicNFTTable("inet", "security", wrapped)
	if err != nil {
		t.Fatalf("second WrapAtomicNFTTable failed: %v", err)
	}
	if strings.Count(wrapped2, "add table inet security") != 1 || strings.Count(wrapped2, "flush table inet security") != 1 {
		t.Fatalf("WrapAtomicNFTTable not idempotent:\n%s", wrapped2)
	}

	// Reject malformed / injection inputs
	badCases := []struct {
		family string
		table  string
		body   string
	}{
		{"invalid", "security", sample},
		{"inet", "bad; rm -rf /", sample},
		{"inet", "", sample},
		{"inet", "security", ""},
		{"inet", "security", "table inet other {}"},
	}
	for _, bc := range badCases {
		if _, err := fwtx.WrapAtomicNFTTable(bc.family, bc.table, bc.body); err == nil {
			t.Fatalf("expected error for invalid input (%q, %q)", bc.family, bc.table)
		}
	}
}

func TestApplyAtomicNFT_TwoPhaseAndCheckAbort(t *testing.T) {
	script := "add table inet sing-box\nflush table inet sing-box\ntable inet sing-box {}\n"

	// 1. Happy path: checkFirst=true executes nft -c -f - then nft -f -
	mr := &mockRunner{}
	if err := fwtx.ApplyAtomicNFT(t.Context(), mr, script, true); err != nil {
		t.Fatalf("ApplyAtomicNFT failed: %v", err)
	}
	if len(mr.calls) != 2 {
		t.Fatalf("expected 2 calls (check + apply), got %d", len(mr.calls))
	}
	if mr.calls[0].Name != "nft" || strings.Join(mr.calls[0].Args, " ") != "-c -f -" || mr.calls[0].Stdin != script {
		t.Fatalf("unexpected first call: %+v", mr.calls[0])
	}
	if mr.calls[1].Name != "nft" || strings.Join(mr.calls[1].Args, " ") != "-f -" || mr.calls[1].Stdin != script {
		t.Fatalf("unexpected second call: %+v", mr.calls[1])
	}

	// 2. Check failure aborts before applying
	failCheck := &mockRunner{
		fn: func(_, name string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "-c" {
				return []byte("syntax error"), errors.New("exit status 1")
			}
			return nil, nil
		},
	}
	if err := fwtx.ApplyAtomicNFT(t.Context(), failCheck, script, true); err == nil {
		t.Fatal("expected error when nft -c -f - fails")
	}
	if len(failCheck.calls) != 1 {
		t.Fatalf("expected apply step skipped when check fails, got %d calls", len(failCheck.calls))
	}

	// 3. Empty script rejected
	if err := fwtx.ApplyAtomicNFT(t.Context(), mr, "   \n", true); err == nil {
		t.Fatal("expected error for blank script")
	}
}

func TestDeleteNFTTableIdempotent(t *testing.T) {
	notFound := &mockRunner{
		fn: func(_, _ string, _ ...string) ([]byte, error) {
			return []byte("Error: No such file or directory\ndelete table inet security\n"), errors.New("exit status 1")
		},
	}
	if err := fwtx.DeleteNFTTableIdempotent(t.Context(), notFound, "inet", "security"); err != nil {
		t.Fatalf("expected nil on missing table, got: %v", err)
	}

	permDenied := &mockRunner{
		fn: func(_, _ string, _ ...string) ([]byte, error) {
			return []byte("Error: Operation not permitted"), errors.New("exit status 1")
		},
	}
	if err := fwtx.DeleteNFTTableIdempotent(t.Context(), permDenied, "inet", "security"); err == nil {
		t.Fatal("expected error on Operation not permitted")
	}
}

func TestApplyIPTablesRestoreNoFlush(t *testing.T) {
	batch := "*mangle\n:SING_BOX - [0:0]\n-F SING_BOX\nCOMMIT\n"

	// 1. Happy path v4 with testFirst=true
	mr := &mockRunner{}
	if err := fwtx.ApplyIPTablesRestoreNoFlush(t.Context(), mr, false, batch, true); err != nil {
		t.Fatalf("ApplyIPTablesRestoreNoFlush(v4) failed: %v", err)
	}
	if len(mr.calls) != 2 {
		t.Fatalf("expected 2 calls (test + restore), got %d", len(mr.calls))
	}
	if mr.calls[0].Name != "iptables-restore" || strings.Join(mr.calls[0].Args, " ") != "--noflush --test" {
		t.Fatalf("unexpected v4 test call: %+v", mr.calls[0])
	}
	if mr.calls[1].Name != "iptables-restore" || strings.Join(mr.calls[1].Args, " ") != "--noflush -w 5" {
		t.Fatalf("unexpected v4 restore call: %+v", mr.calls[1])
	}

	// 2. Fallback when -w 5 unsupported on legacy BusyBox iptables-restore
	noWaitFallback := &mockRunner{
		fn: func(_, name string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if name == "ip6tables-restore" && strings.Contains(joined, "-w 5") {
				return []byte("ip6tables-restore: unrecognized option: w"), errors.New("exit status 2")
			}
			return nil, nil
		},
	}
	if err := fwtx.ApplyIPTablesRestoreNoFlush(t.Context(), noWaitFallback, true, batch, false); err != nil {
		t.Fatalf("expected -w fallback to succeed, got: %v", err)
	}
	if len(noWaitFallback.calls) != 2 || strings.Join(noWaitFallback.calls[1].Args, " ") != "--noflush" {
		t.Fatalf("unexpected fallback calls: %+v", noWaitFallback.calls)
	}

	// 3. Reject missing COMMIT
	if err := fwtx.ApplyIPTablesRestoreNoFlush(t.Context(), mr, false, "*mangle\n-F SING_BOX\n", true); err == nil {
		t.Fatal("expected error for batch missing COMMIT")
	}
}
