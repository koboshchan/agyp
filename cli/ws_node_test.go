package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Exercised by test/ws-cli.test.ts against the real Node adapter and proxy pipeline.
func TestWSNodeIntegration(t *testing.T) {
	base := os.Getenv("AGYP_WS_TEST_BASE")
	if base == "" {
		t.Skip("Node fixture not running")
	}
	u, e := url.Parse(base)
	if e != nil {
		t.Fatal(e)
	}
	tr, e := newWSTransport(u, os.Getenv("AGYP_WS_TEST_KEY"))
	if e != nil {
		t.Fatal(e)
	}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if e = tr.Connect(ctx); e != nil {
		t.Fatal(e)
	}
	bootstrap, _ := http.NewRequestWithContext(ctx, "POST", base+"/v1internal:loadCodeAssist", strings.NewReader("{\"metadata\":{\"ideType\":\"ANTIGRAVITY\"}}"))
	bootResp, e := tr.RoundTrip(bootstrap)
	if e != nil {
		t.Fatal(e)
	}
	bootBody, e := io.ReadAll(bootResp.Body)
	bootResp.Body.Close()
	if e != nil || bootResp.StatusCode != 200 || !strings.Contains(string(bootBody), "cloudaicompanionProject") || !strings.Contains(string(bootBody), "premium-tier") {
		t.Fatal(string(bootBody), e)
	}
	for _, target := range []string{"/api/keys", "/v1internal:fetchAdminControls", "/v1internal:deleteAccount", "/v1internal:refreshToken", "/v1internal/../api/keys"} {
		r, _ := http.NewRequestWithContext(ctx, "POST", base+target, nil)
		if resp, err := tr.RoundTrip(r); err == nil {
			resp.Body.Close()
			t.Error("unsafe websocket endpoint allowed", target)
		}
	}

	// Shared matrix goes through the real authenticated localhost shim and WS client.
	data, err := os.ReadFile("../test/fixtures/cloudcode-paths.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Method  string
		Path    string
		Allowed bool
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	a, err := newAuth(u, os.Getenv("AGYP_WS_TEST_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	h := &shim{auth: a, http: &http.Client{Transport: tr}, capability: "fixture-cap"}
	for _, c := range cases {
		// Non-HTTP URI strings and encoded/traversal variants are exercised by both
		// predicate matrices; actual shim requests below use canonical service paths.
		if !c.Allowed {
			continue
		}
		payload := `{ "metadata":{"ideType":"ANTIGRAVITY"}, "model":"gemini-flash", "request":{"generationConfig":{"maxOutputTokens":10}}, "n":1e+05 }`
		if !strings.HasPrefix(c.Path, "/v1internal") {
			payload = `{ "generationConfig":{"maxOutputTokens":10}, "n":1e+05 }`
		}
		if c.Method == "GET" || c.Method == "HEAD" {
			payload = ""
		}
		req := httptest.NewRequest(c.Method, "/fixture-cap"+c.Path, strings.NewReader(payload)).WithContext(ctx)
		req.Header.Set("X-Compat-Fixture", "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("shim %s %s status %d body %s", c.Method, c.Path, w.Code, w.Body.String())
		}
		if c.Method != "HEAD" && !strings.Contains(w.Body.String(), "fixture-compatible") {
			t.Fatal(w.Body.String())
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := http.NewRequestWithContext(ctx, "POST", base+"/v1internal:generateContent", strings.NewReader("{ \"model\":\"gemini-flash\", \"request\":{\"contents\":[{\"parts\":[{\"text\":\"雪\"}]}]}, \"n\":1e+05 }"))
			resp, err := tr.RoundTrip(r)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != 200 || !strings.Contains(string(b), "OK") {
				t.Errorf("status %d body %q err %v", resp.StatusCode, b, err)
			}
		}()
	}
	wg.Wait()
	// An empty-header GET must not be rejected by schema/omitempty mismatches.
	r, _ := http.NewRequestWithContext(ctx, "GET", base+"/v1/models", nil)
	resp, e := tr.RoundTrip(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	if _, e = io.ReadAll(resp.Body); e != nil || resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, e)
	}
}
