package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "agyp_0123456789abcdef.supersecret"

func authServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *auth, *atomic.Int32) {
	t.Helper()
	count := new(atomic.Int32)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/challenge":
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			if v["keyId"] != "0123456789abcdef" || len(v) != 1 {
				t.Error("invalid challenge payload")
			}
			fmt.Fprintf(w, `{"nonce":"abc_DEF-123","expires":%d}`, time.Now().Add(time.Minute).UnixMilli())
		case "/auth/verify":
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			m := hmac.New(sha256.New, []byte(testKey))
			m.Write([]byte("abc_DEF-123"))
			if v["proof"] != hex.EncodeToString(m.Sum(nil)) || v["client"] != "cli" || v["nonce"] != "abc_DEF-123" {
				t.Error("invalid proof")
			}
			n := count.Add(1)
			fmt.Fprintf(w, `{"token":"session%d","expires":%d}`, n, time.Now().Add(15*time.Minute).UnixMilli())
		default:
			handler(w, r)
		}
	}))
	u, _ := url.Parse(s.URL)
	a, e := newAuth(u, testKey)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s, a, count
}
func TestAuthenticationAndConcurrentRefresh(t *testing.T) {
	_, a, count := authServer(t, func(http.ResponseWriter, *http.Request) {})
	tok, e := a.session(context.Background(), "")
	if e != nil || tok != "session1" {
		t.Fatal(tok, e)
	}
	a.mu.Lock()
	a.expires = time.Now()
	a.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := a.session(context.Background(), ""); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 2 {
		t.Fatal(count.Load())
	}
}
func TestReplay401AndHeaders(t *testing.T) {
	var calls atomic.Int32
	_, a, count := authServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) != "request-body" || r.Header.Get("X-Goog-Api-Key") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("body/header leak")
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("Authorization") != "Bearer session2" {
			t.Error("wrong auth")
		}
		w.Write([]byte("ok"))
	})
	s := httptest.NewServer(&shim{a, client()})
	defer s.Close()
	r, _ := http.NewRequest("POST", s.URL+"/v1/do?x=1", strings.NewReader("request-body"))
	r.Header.Set("Authorization", "Bearer child-secret")
	r.Header.Set("X-Goog-Api-Key", "child-key")
	r.Header.Set("Proxy-Authorization", "secret")
	res, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if string(b) != "ok" || count.Load() != 2 || calls.Load() != 2 {
		t.Fatal(string(b), count.Load(), calls.Load())
	}
}
func TestStreaming(t *testing.T) {
	release := make(chan struct{})
	_, a, _ := authServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("first\n"))
		w.(http.Flusher).Flush()
		<-release
		w.Write([]byte("last\n"))
	})
	s := httptest.NewServer(&shim{a, client()})
	defer s.Close()
	res, e := http.Get(s.URL + "/stream")
	if e != nil {
		close(release)
		t.Fatal(e)
	}
	defer res.Body.Close()
	line, e := bufio.NewReader(res.Body).ReadString('\n')
	close(release)
	if e != nil || line != "first\n" {
		t.Fatal(line, e)
	}
}
func TestRedirectNotFollowed(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer s.Close()
	u, _ := url.Parse(s.URL)
	a, _ := newAuth(u, testKey)
	if _, e := a.session(context.Background(), ""); e == nil {
		t.Fatal("accepted redirect")
	}
	if leaked.Load() {
		t.Fatal("followed redirect")
	}
}
func TestBaseAndKeyValidation(t *testing.T) {
	for _, s := range []string{"http://example.com", "https://u:p@example.com", "https://example.com/?x=1", "file:///tmp/x", "http://127.0.0.1.evil"} {
		if _, e := parseBase(s); e == nil {
			t.Error(s)
		}
	}
	for _, s := range []string{"https://agy.kjt.lol", "http://127.0.0.1:123", "http://[::1]:123"} {
		if _, e := parseBase(s); e != nil {
			t.Error(s, e)
		}
	}
	u, _ := parseBase("https://agy.kjt.lol")
	if _, e := newAuth(u, "oops"); e == nil {
		t.Fatal("accepted invalid key")
	}
}
func TestChildEnv(t *testing.T) {
	e := childEnv([]string{"AGYP_TOKEN=" + testKey, "https_proxy=bad", "CLOUD_CODE_URL=bad", "all_proxy=bad", "OK=yes"}, "http://127.0.0.1:123")
	joined := strings.Join(e, "\n")
	if strings.Contains(joined, testKey) || strings.Contains(joined, "bad") || !strings.Contains(joined, "OK=yes") {
		t.Fatal("bad environment")
	}
	for _, k := range []string{"CLOUD_CODE_URL", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if !strings.Contains(joined, k+"=http://127.0.0.1:123") {
			t.Error(k)
		}
	}
}
func TestLaunch(t *testing.T) {
	if os.Getenv("AGYP_TEST_CHILD") == "1" {
		if os.Getenv("AGYP_TOKEN") != "" || !strings.HasPrefix(os.Getenv("CLOUD_CODE_URL"), "http://127.0.0.1:") {
			os.Exit(9)
		}
		os.Exit(7)
	}
	s, _, _ := authServer(t, func(http.ResponseWriter, *http.Request) {})
	t.Setenv("AGYP_BASE", s.URL)
	t.Setenv("AGYP_TOKEN", testKey)
	t.Setenv("AGYP_TEST_CHILD", "1")
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	if code := run([]string{"--", exe, "-test.run=^TestLaunch$"}); code != 7 {
		t.Fatal(code)
	}
}
func TestCONNECT(t *testing.T) {
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		c, e := echo.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	_, a, _ := authServer(t, func(http.ResponseWriter, *http.Request) {})
	s := httptest.NewServer(&shim{a, client()})
	defer s.Close()
	u, _ := url.Parse(s.URL)
	c, e := net.Dial("tcp", u.Host)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nhello", echo.Addr(), echo.Addr())
	r := bufio.NewReader(c)
	line, _ := r.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatal(line)
	}
	r.ReadString('\n')
	b := make([]byte, 5)
	if _, e = io.ReadFull(r, b); e != nil || string(b) != "hello" {
		t.Fatal(string(b), e)
	}
}
func TestExpiryFormats(t *testing.T) {
	now := time.Now()
	for _, v := range []any{now.Unix(), now.UnixMilli(), now.UTC().Format(time.RFC3339Nano)} {
		b, _ := json.Marshal(v)
		if _, e := expiry(b); e != nil {
			t.Fatal(e)
		}
	}
}
func TestBuild(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	c := exec.Command("go", "build", "-o", t.TempDir()+"/agyp", ".")
	if out, e := c.CombinedOutput(); e != nil {
		t.Fatalf("%s %v", out, e)
	}
}

func TestUpstreamRedirectAndRepeated401(t *testing.T) {
	for _, status := range []int{307, 401} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			_, a, n := authServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "https://example.invalid")
				w.WriteHeader(status)
			})
			s := httptest.NewServer(&shim{a, client()})
			defer s.Close()
			res, e := client().Get(s.URL + "/v1")
			if e != nil {
				t.Fatal(e)
			}
			res.Body.Close()
			if status == 307 && (res.StatusCode != 502 || calls.Load() != 1) {
				t.Fatal(res.StatusCode, calls.Load())
			}
			if status == 401 && (res.StatusCode != 401 || n.Load() != 2 || calls.Load() != 2) {
				t.Fatal(res.StatusCode, n.Load(), calls.Load())
			}
		})
	}
}
func TestUnrelatedHTTPDirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "original" {
			t.Error("changed unrelated auth")
		}
		w.Write([]byte("direct"))
	}))
	defer target.Close()
	_, a, n := authServer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("wrong remote") })
	u, _ := url.Parse(target.URL)
	direct := client()
	direct.Transport = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, u.Host)
	}}
	r := httptest.NewRequest("GET", "http://example.test/test", nil)
	r.Header.Set("Authorization", "original")
	w := httptest.NewRecorder()
	(&shim{a, direct}).ServeHTTP(w, r)
	if w.Body.String() != "direct" || n.Load() != 0 {
		t.Fatal(w.Body.String(), n.Load())
	}
}
