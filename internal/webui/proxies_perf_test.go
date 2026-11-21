package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func buildSyntheticClashConnectionsPayload(n int) []byte {
	var buf bytes.Buffer
	buf.Grow(n * 320)
	buf.WriteString(`{"downloadTotal":9876543210,"uploadTotal":123456789,"memory":45678912,"connections":[`)
	for i := range n {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf,
			`{"id":"conn-%d","upload":%d,"download":%d,"start":"2026-11-21T12:00:00Z","chains":["node-%d","Proxy","Selector"],"rule":"rule_set=geosite-youtube","rulePayload":"youtube.com","metadata":{"network":"tcp","type":"mixed","sourceIP":"192.168.100.%d","destinationIP":"203.0.113.%d","sourcePort":"%d","destinationPort":"443","host":"rr%d---sn-test.googlevideo.com","dnsMode":"normal"}}`,
			i, i*128, i*2048, i%5, (i%200)+10, (i%200)+10, 40000+i, i%10,
		)
	}
	buf.WriteString(`]}`)
	return buf.Bytes()
}

func TestDecodeClashConnectionsSummary(t *testing.T) {
	t.Run("600 realistic connections", func(t *testing.T) {
		payload := buildSyntheticClashConnectionsPayload(600)
		up, down, cnt, ok := decodeClashConnectionsSummary(bytes.NewReader(payload))
		if !ok || up != 123456789 || down != 9876543210 || cnt != 600 {
			t.Fatalf("got (up=%d, down=%d, cnt=%d, ok=%v), want (123456789, 9876543210, 600, true)", up, down, cnt, ok)
		}
	})

	t.Run("connections key before totals and extra nested values", func(t *testing.T) {
		raw := `{
			"connections": [
				{"id":"a","extra":{"deep":[1,true,null,{"k":"[escaped] \"quote\" }"}]}},
				{"id":"b","chains":["Direct"]}
			],
			"unknownObj": {"nested":[{"arr":[1,2,3]}]},
			"unknownArr": [1,2,3],
			"uploadTotal": 42,
			"downloadTotal": 84
		}`
		up, down, cnt, ok := decodeClashConnectionsSummary(strings.NewReader(raw))
		if !ok || up != 42 || down != 84 || cnt != 2 {
			t.Fatalf("got (%d, %d, %d, %v), want (42, 84, 2, true)", up, down, cnt, ok)
		}
	})

	t.Run("empty connections array", func(t *testing.T) {
		raw := `{"uploadTotal":100,"downloadTotal":200,"connections":[]}`
		up, down, cnt, ok := decodeClashConnectionsSummary(strings.NewReader(raw))
		if !ok || up != 100 || down != 200 || cnt != 0 {
			t.Fatalf("got (%d, %d, %d, %v)", up, down, cnt, ok)
		}
	})

	t.Run("null connections", func(t *testing.T) {
		raw := `{"uploadTotal":10,"downloadTotal":20,"connections":null}`
		up, down, cnt, ok := decodeClashConnectionsSummary(strings.NewReader(raw))
		if !ok || up != 10 || down != 20 || cnt != 0 {
			t.Fatalf("got (%d, %d, %d, %v)", up, down, cnt, ok)
		}
	})

	t.Run("malformed and truncated inputs return false", func(t *testing.T) {
		for _, bad := range []string{
			``,
			`not-json`,
			`[]`,
			`{"uploadTotal":1,"connections":[{}`,
			`{"uploadTotal":"bad","connections":[]}`,
			`{"connections":{}}`,
			`{"uploadTotal":1,"downloadTotal":2,"connections":[{"id":1}`,
		} {
			if _, _, _, ok := decodeClashConnectionsSummary(strings.NewReader(bad)); ok {
				t.Fatalf("expected ok=false for malformed input %q", bad)
			}
		}
	})
}

func TestFetchClashConnections_ConcurrentPoolRace(t *testing.T) {
	payload := buildSyntheticClashConnectionsPayload(250)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connections" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 15 {
				up, down, cnt, ok := fetchClashConnections(t.Context(), srv.URL, "")
				if !ok || up != 123456789 || down != 9876543210 || cnt != 250 {
					t.Errorf("unexpected fetch result (%d, %d, %d, %v)", up, down, cnt, ok)
					return
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkDecodeClashConnections_LegacyUnmarshal(b *testing.B) {
	payload := buildSyntheticClashConnectionsPayload(800)
	b.ReportAllocs()
	for b.Loop() {
		var connDoc struct {
			UploadTotal   int64 `json:"uploadTotal"`
			DownloadTotal int64 `json:"downloadTotal"`
			Connections   []any `json:"connections"`
		}
		if err := json.Unmarshal(payload, &connDoc); err != nil {
			b.Fatal(err)
		}
		if len(connDoc.Connections) != 800 {
			b.Fatalf("got %d", len(connDoc.Connections))
		}
	}
}

func BenchmarkDecodeClashConnections_Streaming(b *testing.B) {
	payload := buildSyntheticClashConnectionsPayload(800)
	var r bytes.Reader
	b.ReportAllocs()
	for b.Loop() {
		r.Reset(payload)
		_, _, cnt, ok := decodeClashConnectionsSummary(&r)
		if !ok || cnt != 800 {
			b.Fatalf("got (%d, %v)", cnt, ok)
		}
	}
}
