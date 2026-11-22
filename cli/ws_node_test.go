package main

import (
	"context"
	"io"
	"net/http"
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
