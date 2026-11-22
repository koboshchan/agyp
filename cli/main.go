// agyp runs an application behind an authenticated, loopback-only Cloud Code shim.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// version is set from the release tag at build time.
var version = "dev"

var keyPattern = regexp.MustCompile(`^agyp_([0-9a-fA-F]{16})\.[A-Za-z0-9_-]+$`)
var noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func parseBase(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil {
		return nil, errors.New("invalid AGYP_BASE")
	}
	local := u.Hostname() == "localhost" || net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback()
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && local)) {
		return nil, errors.New("AGYP_BASE requires HTTPS (HTTP allowed only for loopback development)")
	}
	return u, nil
}
func client() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: 30 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type auth struct {
	mu             sync.Mutex
	base           *url.URL
	key, id, token string
	expires        time.Time
	http           *http.Client
}

func newAuth(base *url.URL, key string) (*auth, error) {
	m := keyPattern.FindStringSubmatch(key)
	if m == nil {
		return nil, errors.New("AGYP_TOKEN must have form agyp_<16hex>.<secret>")
	}
	return &auth{base: base, key: key, id: m[1], http: client()}, nil
}

// expiry accepts ISO dates, Unix seconds and JavaScript milliseconds.
func expiry(raw json.RawMessage) (time.Time, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return time.Parse(time.RFC3339Nano, s)
	}
	var n int64
	if e := json.Unmarshal(raw, &n); e != nil {
		return time.Time{}, e
	}
	if n > 100000000000 {
		return time.UnixMilli(n), nil
	}
	return time.Unix(n, 0), nil
}
func (a *auth) post(ctx context.Context, path string, in, out any) error {
	b, _ := json.Marshal(in)
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	r, e := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := a.http.Do(r)
	if e != nil {
		return errors.New("authentication transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("authentication failed (HTTP %d)", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(out)
}
func (a *auth) session(ctx context.Context, rejected string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Until(a.expires) > 30*time.Second && (rejected == "" || a.token != rejected) {
		return a.token, nil
	}
	var c struct {
		Nonce   string          `json:"nonce"`
		Expires json.RawMessage `json:"expires"`
	}
	if e := a.post(ctx, "/auth/challenge", map[string]string{"keyId": a.id}, &c); e != nil {
		return "", e
	}
	ex, e := expiry(c.Expires)
	if e != nil || !ex.After(time.Now()) || !noncePattern.MatchString(c.Nonce) {
		return "", errors.New("invalid authentication challenge")
	}
	mac := hmac.New(sha256.New, []byte(a.key))
	mac.Write([]byte(c.Nonce))
	var v struct {
		Token   string          `json:"token"`
		Expires json.RawMessage `json:"expires"`
	}
	if e = a.post(ctx, "/auth/verify", map[string]string{"keyId": a.id, "nonce": c.Nonce, "proof": hex.EncodeToString(mac.Sum(nil)), "client": "cli"}, &v); e != nil {
		return "", e
	}
	ex, e = expiry(v.Expires)
	if e != nil || time.Until(ex) <= 30*time.Second || v.Token == "" || strings.ContainsAny(v.Token, "\r\n") {
		return "", errors.New("invalid authentication session")
	}
	a.token = v.Token
	a.expires = ex
	return a.token, nil
}

type shim struct {
	auth       *auth
	http       *http.Client
	capability string
}

var hop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"}

func clean(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, n := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(n))
		}
	}
	for _, n := range hop {
		h.Del(n)
	}
}

var inferencePath = regexp.MustCompile(`^/v1internal:(generateContent|streamGenerateContent|countTokens|fetchAvailableModels)$`)
var modelActionPath = regexp.MustCompile(`^/v1(beta)?/models/[A-Za-z0-9._-]+:(generateContent|streamGenerateContent|countTokens)$`)

func inferenceAllowed(method, path string) bool {
	return method == "POST" && (inferencePath.MatchString(path) || modelActionPath.MatchString(path)) ||
		method == "GET" && (path == "/v1/models" || path == "/v1beta/models")
}
func (s *shim) proxyAuthorized(r *http.Request) bool {
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("agyp:"+s.capability))
	return s.capability != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte(expected)) == 1
}
func (s *shim) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" || r.URL.IsAbs() {
		if !s.proxyAuthorized(r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="agyp"`)
			http.Error(w, "proxy authentication required", 407)
			return
		}
		if r.Method == "CONNECT" {
			s.connect(w, r)
			return
		}
		if r.URL.Scheme != "http" || r.URL.User != nil {
			http.Error(w, "invalid proxy target", 400)
			return
		}
		// Only exact Cloud Code hosts may exchange the remote inference credential.
		if r.URL.Hostname() != "cloudcode-pa.googleapis.com" && r.URL.Hostname() != "daily-cloudcode-pa.googleapis.com" {
			s.forward(w, r, r.URL, nil)
			return
		}
	} else {
		prefix := "/" + s.capability
		if s.capability == "" || !strings.HasPrefix(r.URL.Path, prefix+"/") || r.URL.RawPath != "" {
			http.Error(w, "local capability required", 403)
			return
		}
		r = r.Clone(r.Context())
		u := *r.URL
		u.Path = strings.TrimPrefix(u.Path, prefix)
		r.URL = &u
	}
	if r.URL.RawPath != "" || !inferenceAllowed(r.Method, r.URL.Path) {
		http.Error(w, "inference endpoint forbidden", 403)
		return
	}
	u := *s.auth.base
	u.Path = strings.TrimRight(u.Path, "/") + r.URL.Path
	u.RawPath = ""
	u.RawQuery = r.URL.RawQuery
	s.forward(w, r, &u, s.auth)
}
func (s *shim) forward(w http.ResponseWriter, r *http.Request, u *url.URL, a *auth) {
	// Spool to a private, immediately unlinked file for bounded-memory replay of POST bodies.
	var body *os.File
	if r.Body != nil && r.Body != http.NoBody {
		var e error
		body, e = os.CreateTemp("", "agyp-body-*")
		if e != nil {
			http.Error(w, "body spool failed", 502)
			return
		}
		os.Remove(body.Name())
		defer body.Close()
		if _, e = io.Copy(body, r.Body); e != nil {
			http.Error(w, "body read failed", 400)
			return
		}
	}
	token := ""
	var e error
	if a != nil {
		token, e = a.session(r.Context(), "")
		if e != nil {
			http.Error(w, "authentication failed", 502)
			return
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		q := r.Clone(r.Context())
		q.URL = u
		q.Host = u.Host
		q.RequestURI = ""
		q.Header = r.Header.Clone()
		clean(q.Header)
		q.Header.Del("Authorization")
		q.Header.Del("X-Goog-Api-Key")
		q.Header.Del("Cookie")
		if body != nil {
			body.Seek(0, 0)
			q.Body = io.NopCloser(body)
		}
		if a != nil {
			q.Header.Del("Authorization")
			q.Header.Del("X-Goog-Api-Key")
			q.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := s.http.Do(q)
		if err != nil {
			http.Error(w, "upstream transport failed", 502)
			return
		}
		if a != nil && resp.StatusCode == 401 && attempt == 0 {
			resp.Body.Close()
			token, e = a.session(r.Context(), token)
			if e != nil {
				http.Error(w, "authentication failed", 502)
				return
			}
			continue
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && a != nil {
			resp.Body.Close()
			http.Error(w, "upstream redirect rejected", http.StatusBadGateway)
			return
		}
		clean(resp.Header)
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, e := w.Write(buf[:n]); e != nil {
					break
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			if err != nil {
				break
			}
		}
		resp.Body.Close()
		return
	}
}
func (s *shim) connect(w http.ResponseWriter, r *http.Request) {
	host, port, e := net.SplitHostPort(r.Host)
	if e != nil || host == "" || port == "" {
		http.Error(w, "invalid CONNECT target", 400)
		return
	}
	up, e := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(r.Context(), "tcp", r.Host)
	if e != nil {
		http.Error(w, "CONNECT failed", 502)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "CONNECT unsupported", 500)
		return
	}
	down, rw, e := hj.Hijack()
	if e != nil {
		up.Close()
		return
	}
	defer down.Close()
	defer up.Close()
	rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if rw.Flush() != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		io.Copy(up, rw)
		if t, ok := up.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		close(done)
	}()
	io.Copy(down, up)
	down.Close()
	up.Close()
	<-done
}
func childEnv(env []string, addr, capability string) []string {
	out := []string{}
	for _, v := range env {
		k, _, _ := strings.Cut(v, "=")
		switch strings.ToUpper(k) {
		case "AGYP_TOKEN", "CLOUD_CODE_URL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		out = append(out, v)
	}
	proxyURL, _ := url.Parse(addr)
	proxyURL.User = url.UserPassword("agyp", capability)
	proxy := proxyURL.String()
	return append(out, "CLOUD_CODE_URL="+addr+"/"+capability, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "http_proxy="+proxy, "https_proxy="+proxy, "NO_PROXY=localhost,127.0.0.1,::1,speech.googleapis.com", "no_proxy=localhost,127.0.0.1,::1,speech.googleapis.com")
}
func debugPhase(phase string) {
	if os.Getenv("AGYP_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "agyp debug phase=%s pid=%d at=%s\n", phase, os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
	}
}

// terminalDeliveredInterrupt reports whether the foreground terminal already
// delivered SIGINT to both us and the child. os/signal does not expose siginfo,
// so a PID-directed SIGINT in the same cooked-terminal state is indistinguishable;
// the bounded shutdown below still guarantees it cannot leave a stuck child.
func terminalDeliveredInterrupt(child *os.Process) bool {
	group, err := syscall.Getpgid(child.Pid)
	if err != nil || group != syscall.Getpgrp() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	stty := exec.CommandContext(ctx, "stty", "-a")
	stty.Stdin = os.Stdin
	state, err := stty.Output()
	if err != nil {
		return false
	}
	isig := false
	for _, field := range strings.Fields(string(state)) {
		if strings.Trim(field, ";") == "isig" {
			isig = true
		}
	}
	if !isig {
		return false
	}
	// ps exposes the controlling terminal's foreground pgid on Linux and macOS,
	// without platform-specific ioctl structures or unsafe pointers.
	ps := exec.CommandContext(ctx, "ps", "-o", "tpgid=", "-p", fmt.Sprint(os.Getpid()))
	out, err := ps.Output()
	if err != nil {
		return false
	}
	var foreground int
	_, err = fmt.Sscan(string(out), &foreground)
	return err == nil && foreground == group
}

func run(args []string) int {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(os.Stdout, "agyp "+version)
		return 0
	}
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agyp -- agy [args...]")
		return 2
	}
	base, e := parseBase(os.Getenv("AGYP_BASE"))
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	a, e := newAuth(base, os.Getenv("AGYP_TOKEN"))
	os.Unsetenv("AGYP_TOKEN")
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	// Register before any network operation. Keep the child in the foreground
	// process group inherited from the shell: a separate background group cannot
	// read the controlling terminal (SIGTTIN), including its Ctrl-C input.
	root, interrupt := context.WithCancel(context.Background())
	defer interrupt()
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	var interrupted atomic.Int32
	var processMu sync.Mutex
	var process *os.Process
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case sig := <-signals:
			v := sig.(syscall.Signal)
			interrupted.Store(int32(v))
			interrupt()
			processMu.Lock()
			child := process
			if child != nil && (v != syscall.SIGINT || !terminalDeliveredInterrupt(child)) {
				_ = child.Signal(v)
			}
			processMu.Unlock()
			if child != nil {
				select {
				case <-finished:
					return
				case <-time.After(3 * time.Second):
					_ = child.Kill()
				}
			}
		case <-finished:
		}
	}()
	ctx, cancel := context.WithTimeout(root, 30*time.Second)
	debugPhase("auth_start")
	_, e = a.session(ctx, "")
	debugPhase("auth_end")
	cancel()
	if e != nil {
		if n := interrupted.Load(); n != 0 {
			return 128 + int(n)
		}
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		fmt.Fprintln(os.Stderr, "cannot start local proxy")
		return 1
	}
	capBytes := make([]byte, 32)
	if _, e = rand.Read(capBytes); e != nil {
		ln.Close()
		fmt.Fprintln(os.Stderr, "cannot generate local capability")
		return 1
	}
	capability := base64.RawURLEncoding.EncodeToString(capBytes)
	srv := &http.Server{Handler: &shim{a, client(), capability}, ReadHeaderTimeout: 15 * time.Second}
	go srv.Serve(ln)
	debugPhase("proxy_bound")
	defer srv.Close()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = childEnv(os.Environ(), "http://"+ln.Addr().String(), capability)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Snapshot terminal settings before the TUI enters raw mode. Restore even
	// when an unresponsive child needs forced termination.
	stty := exec.Command("stty", "-g")
	stty.Stdin = os.Stdin
	if state, err := stty.Output(); err == nil {
		defer func() {
			restore := exec.Command("stty", strings.TrimSpace(string(state)))
			restore.Stdin = os.Stdin
			_ = restore.Run()
		}()
	}
	processMu.Lock()
	if n := interrupted.Load(); n != 0 {
		processMu.Unlock()
		return 128 + int(n)
	}
	debugPhase("child_start")
	e = cmd.Start()
	if e == nil {
		process = cmd.Process
		debugPhase("child_started")
	}
	processMu.Unlock()
	if e != nil {
		fmt.Fprintln(os.Stderr, "cannot start child command")
		return 1
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case e := <-done:
			if n := interrupted.Load(); n != 0 {
				return 128 + int(n)
			}
			if e == nil {
				return 0
			}
			var x *exec.ExitError
			if errors.As(e, &x) {
				if st, ok := x.Sys().(syscall.WaitStatus); ok && st.Signaled() {
					return 128 + int(st.Signal())
				}
				return x.ExitCode()
			}
			return 1
		}
	}
}
func main() { os.Exit(run(os.Args[1:])) }
