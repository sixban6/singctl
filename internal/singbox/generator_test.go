package singbox

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"singctl/internal/config"
)

func TestGenerator_MultiSubscription_PartialFailure(t *testing.T) {
	// Server 1: returns HTML error (0 nodes)
	tsHTML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Login Error</body></html>"))
	}))
	defer tsHTML.Close()

	// Server 2: Closed server (connection refused)
	tsClosed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := tsClosed.URL
	tsClosed.Close()

	// Server 3: returns valid base64 subscription node
	tsValid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// hysteria2://dummy-user:dummy-pass@mock-node.example.com:443?sni=mock-node.example.com#sec_mock_hy2
		w.Write([]byte("aHlzdGVyaWEyOi8vZHVtbXktdXNlcjpkdW1teS1wYXNzQG1vY2stbm9kZS5leGFtcGxlLmNvbTo0NDM/c25pPW1vY2stbm9kZS5leGFtcGxlLmNvbSNzZWNfbW9ja19oeTI="))
	}))
	defer tsValid.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "sub_html", URL: tsHTML.URL},
			{Name: "sub_closed", URL: closedURL},
			{Name: "sub_valid", URL: tsValid.URL},
		},
	}

	generator := NewConfigGenerator(cfg)
	res, err := generator.GenerateForPlatform("linux")
	if err != nil {
		t.Fatalf("expected generation to succeed by skipping failed subs, got error: %v", err)
	}

	if !strings.Contains(res, "sub_valid") && !strings.Contains(res, "mock-node.example.com") {
		t.Fatalf("generated config should contain nodes from valid sub, got: %s", res)
	}
}

func TestGenerator_MultiSubscription_AllFail(t *testing.T) {
	tsHTML1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Error 1</body></html>"))
	}))
	defer tsHTML1.Close()

	tsHTML2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Error 2</body></html>"))
	}))
	defer tsHTML2.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "bad_sub1", URL: tsHTML1.URL},
			{Name: "bad_sub2", URL: tsHTML2.URL},
		},
	}

	generator := NewConfigGenerator(cfg)
	_, err := generator.GenerateForPlatform("linux")
	if err == nil {
		t.Fatal("expected error when all subscriptions fail, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "bad_sub1") || !strings.Contains(errMsg, "bad_sub2") {
		t.Fatalf("error message should identify each failed subscription name, got: %s", errMsg)
	}
}

func TestGenerator_SingleSubscription_Failure(t *testing.T) {
	tsHTML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Error</body></html>"))
	}))
	defer tsHTML.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "single_bad", URL: tsHTML.URL},
		},
	}

	generator := NewConfigGenerator(cfg)
	_, err := generator.GenerateForPlatform("linux")
	if err == nil {
		t.Fatal("expected error when single subscription fails, got nil")
	}

	if !strings.Contains(err.Error(), "single_bad") {
		t.Fatalf("error message should identify subscription name, got: %v", err)
	}
}

func TestGenerator_ZeroSubscriptions(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{},
	}

	generator := NewConfigGenerator(cfg)
	_, err := generator.GenerateForPlatform("linux")
	if err == nil {
		t.Fatal("expected error when subs is empty, got nil")
	}
}
