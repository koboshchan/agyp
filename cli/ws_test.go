package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func socketServer(t *testing.T, handler func(*websocket.Conn, int32)) (*wsTransport, *atomic.Int32) {
	t.Helper()
	var connections atomic.Int32
	upgrader := websocket.Upgrader{Subprotocols: []string{"agyp.v1"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/transport" {
			t.Error("unexpected REST request", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		c, e := upgrader.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		n := connections.Add(1)
		nonce, salt := strings.Repeat("n", 43), strings.Repeat("s", 43)
		if c.WriteJSON(wsFrame{Type: "challenge", Nonce: nonce, Salt: salt, Expires: time.Now().Add(time.Second * 5).UnixMilli()}) != nil {
			return
		}
		var a wsFrame
		if c.ReadJSON(&a) != nil {
			return
		}
		mac := hmac.New(sha256.New, []byte(testKey))
		mac.Write([]byte("agyp-ws-v1\n" + salt + "\n" + nonce))
		if a.Type != "auth" || a.KeyID != "0123456789abcdef" || a.Proof != hex.EncodeToString(mac.Sum(nil)) {
			t.Error("invalid websocket auth")
			return
		}
		if c.WriteJSON(wsFrame{Type: "ready"}) != nil {
			return
		}
		handler(c, n)
	}))
	u, _ := url.Parse(srv.URL)
	tr, e := newWSTransport(u, testKey)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { tr.Close(); srv.Close() })
	return tr, &connections
}
func TestWSMultiplexOneConnection(t *testing.T) {
	tr, count := socketServer(t, func(c *websocket.Conn, _ int32) {
		requests := map[string]string{}
		ends := []string{}
		for len(ends) < 4 {
			var f wsFrame
			if c.ReadJSON(&f) != nil {
				return
			}
			switch f.Type {
			case "start":
				requests[f.ID] = ""
				if f.Headers["Authorization"] != "" || f.Headers["Cookie"] != "" {
					t.Error("credential leaked")
				}
			case "data":
				requests[f.ID] += string(f.Data)
			case "end":
				ends = append(ends, f.ID)
			}
		}
		// Deliberately complete in reverse order, with interleaved chunks.
		for i := len(ends) - 1; i >= 0; i-- {
			c.WriteJSON(wsFrame{Type: "headers", ID: ends[i], Status: 200, Headers: map[string]string{"content-type": "text/event-stream"}})
		}
		for i := len(ends) - 1; i >= 0; i-- {
			c.WriteJSON(wsFrame{Type: "data", ID: ends[i], Data: []byte(requests[ends[i]])})
		}
		for i := len(ends) - 1; i >= 0; i-- {
			c.WriteJSON(wsFrame{Type: "end", ID: ends[i]})
		}
		for {
			var f wsFrame
			if c.ReadJSON(&f) != nil {
				return
			}
		}
	})
	var wg sync.WaitGroup
	for _, body := range []string{"one", "two", "three", "雪"} {
		wg.Add(1)
		go func(body string) {
			defer wg.Done()
			r, _ := http.NewRequest("POST", tr.base.String()+"/v1internal:generateContent", strings.NewReader(body))
			r.Header.Set("Authorization", "secret")
			r.Header.Set("Cookie", "secret")
			resp, e := tr.RoundTrip(r)
			if e != nil {
				t.Error(e)
				return
			}
			defer resp.Body.Close()
			b, e := io.ReadAll(resp.Body)
			if e != nil || string(b) != body {
				t.Errorf("body %q err %v", b, e)
			}
		}(body)
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatal("expected one connection", count.Load())
	}
}
func TestWSDisconnectDoesNotReplayAndNewRequestReauthenticates(t *testing.T) {
	var dispatches atomic.Int32
	tr, count := socketServer(t, func(c *websocket.Conn, n int32) {
		for {
			var f wsFrame
			if c.ReadJSON(&f) != nil {
				return
			}
			if f.Type != "end" {
				continue
			}
			dispatches.Add(1)
			if n == 1 {
				c.WriteJSON(wsFrame{Type: "headers", ID: f.ID, Status: 200})
				c.WriteJSON(wsFrame{Type: "data", ID: f.ID, Data: []byte("partial")})
				return
			}
			c.WriteJSON(wsFrame{Type: "headers", ID: f.ID, Status: 200})
			c.WriteJSON(wsFrame{Type: "data", ID: f.ID, Data: []byte("new")})
			c.WriteJSON(wsFrame{Type: "end", ID: f.ID})
		}
	})
	request := func() (*http.Response, error) {
		r, _ := http.NewRequest("POST", tr.base.String()+"/v1internal:generateContent", strings.NewReader("{}"))
		return tr.RoundTrip(r)
	}
	r, e := request()
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(r.Body)
	r.Body.Close()
	if string(b) != "partial" || !errors.Is(e, errWSInterrupted) {
		t.Fatal(string(b), e)
	}
	if count.Load() != 1 || dispatches.Load() != 1 {
		t.Fatal("ambiguous request replayed")
	}
	r, e = request()
	if e != nil {
		t.Fatal(e)
	}
	b, e = io.ReadAll(r.Body)
	r.Body.Close()
	if string(b) != "new" || e != nil {
		t.Fatal(string(b), e)
	}
	if count.Load() != 2 || dispatches.Load() != 2 {
		t.Fatal(count.Load(), dispatches.Load())
	}
}
func TestWSDisconnectBeforeHeadersDoesNotReplay(t *testing.T) {
	var dispatches atomic.Int32
	tr, count := socketServer(t, func(c *websocket.Conn, _ int32) {
		for {
			var f wsFrame
			if c.ReadJSON(&f) != nil {
				return
			}
			if f.Type == "end" {
				dispatches.Add(1)
				return
			}
		}
	})
	r, _ := http.NewRequest("POST", tr.base.String()+"/v1internal:generateContent", strings.NewReader("{}"))
	if _, e := tr.RoundTrip(r); !errors.Is(e, errWSInterrupted) {
		t.Fatal(e)
	}
	if count.Load() != 1 || dispatches.Load() != 1 {
		t.Fatal("request replayed")
	}
}
func TestWSCancellationAndSlowStreamIsolation(t *testing.T) {
	canceled := make(chan struct{}, 2)
	tr, _ := socketServer(t, func(c *websocket.Conn, _ int32) {
		for {
			var f wsFrame
			if c.ReadJSON(&f) != nil {
				return
			}
			switch f.Type {
			case "cancel":
				select {
				case canceled <- struct{}{}:
				default:
				}
			case "end":
				c.WriteJSON(wsFrame{Type: "headers", ID: f.ID, Status: 200})
				if f.ID != "" {
					for i := 0; i < 40; i++ {
						if c.WriteJSON(wsFrame{Type: "data", ID: f.ID, Data: make([]byte, 32768)}) != nil {
							return
						}
					}
				}
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	r, _ := http.NewRequestWithContext(ctx, "POST", tr.base.String()+"/v1internal:generateContent", nil)
	resp, e := tr.RoundTrip(r)
	if e != nil {
		t.Fatal(e)
	}
	// A paused consumer overflows its bounded queue, not the socket reader.
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("slow stream did not cancel")
	}
	b, e := io.ReadAll(resp.Body)
	resp.Body.Close()
	cancel()
	if e == nil || len(b) > 16*32768 {
		t.Fatal("unbounded queue or missing failure", len(b), e)
	}
}

type blockingWSBody struct {
	started, closed chan struct{}
	start, close    sync.Once
}

func (b *blockingWSBody) Read(p []byte) (int, error) {
	b.start.Do(func() { close(b.started) })
	<-b.closed
	return 0, io.ErrClosedPipe
}
func (b *blockingWSBody) Close() error { b.close.Do(func() { close(b.closed) }); return nil }
func TestWSCancelUnblocksUploadAndPreservesOtherStreams(t *testing.T) {
	canceled := make(chan struct{})
	tr, _ := socketServer(t, func(c *websocket.Conn, _ int32) {
		canceledID := ""
		for {
			var f wsFrame
			if c.ReadJSON(&f) != nil {
				return
			}
			if f.ID == canceledID && f.Type != "cancel" {
				t.Error("upload frame after cancel", f.Type)
				return
			}
			if f.Type == "cancel" {
				if canceledID == "" {
					canceledID = f.ID
					close(canceled)
				}
				continue
			}
			if f.Type == "end" {
				c.WriteJSON(wsFrame{Type: "headers", ID: f.ID, Status: 200})
				c.WriteJSON(wsFrame{Type: "data", ID: f.ID, Data: []byte("OK")})
				c.WriteJSON(wsFrame{Type: "end", ID: f.ID})
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &blockingWSBody{started: make(chan struct{}), closed: make(chan struct{})}
	r, _ := http.NewRequestWithContext(ctx, "POST", tr.base.String()+"/v1internal:generateContent", body)
	done := make(chan error, 1)
	go func() { _, e := tr.RoundTrip(r); done <- e }()
	<-body.started
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("missing cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("body read hung after cancel")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("cancel frame missing")
	}
	r, _ = http.NewRequest("POST", tr.base.String()+"/v1internal:generateContent", strings.NewReader("{}"))
	resp, e := tr.RoundTrip(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(resp.Body)
	if string(b) != "OK" || e != nil {
		t.Fatal(string(b), e)
	}
}
