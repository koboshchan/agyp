package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var errWSInterrupted = errors.New("agyp transport interrupted; request was not replayed")

type wsFrame struct {
	Type     string            `json:"type"`
	ID       string            `json:"id,omitempty"`
	Nonce    string            `json:"nonce,omitempty"`
	Salt     string            `json:"salt,omitempty"`
	Expires  int64             `json:"expires,omitempty"`
	KeyID    string            `json:"keyId,omitempty"`
	Proof    string            `json:"proof,omitempty"`
	Method   string            `json:"method,omitempty"`
	Path     string            `json:"path,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Deadline int64             `json:"deadline,omitempty"`
	Status   int               `json:"status,omitempty"`
	Data     []byte            `json:"data,omitempty"`
	Message  string            `json:"message,omitempty"`
}
type wsResult struct {
	response *http.Response
	err      error
}
type wsCall struct {
	id      string
	result  chan wsResult
	chunks  chan []byte
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	err     error
	headers bool
}

func (p *wsCall) finish(err error) {
	p.once.Do(func() { p.mu.Lock(); p.err = err; p.mu.Unlock(); close(p.done) })
}
func (p *wsCall) failure() error { p.mu.Lock(); defer p.mu.Unlock(); return p.err }

type wsConn struct {
	socket  *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	calls   map[string]*wsCall
	dead    bool
}

func (c *wsConn) send(f wsFrame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if e := c.socket.WriteJSON(f); e != nil {
		c.fail()
		return errWSInterrupted
	}
	return nil
}
func (c *wsConn) fail() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	for _, p := range c.calls {
		p.finish(errWSInterrupted)
	}
	c.calls = map[string]*wsCall{}
	c.mu.Unlock()
	c.socket.Close()
}
func (c *wsConn) remove(id string) { c.mu.Lock(); delete(c.calls, id); c.mu.Unlock() }
func (c *wsConn) read() {
	defer c.fail()
	for {
		var f wsFrame
		if c.socket.ReadJSON(&f) != nil {
			return
		}
		c.mu.Lock()
		p := c.calls[f.ID]
		c.mu.Unlock()
		if p == nil { // Completion/cancellation may race a final queued frame.
			continue
		}
		switch f.Type {
		case "headers":
			if p.headers || f.Status < 100 || f.Status > 599 {
				return
			}
			p.headers = true
			h := make(http.Header)
			for k, v := range f.Headers {
				if strings.ContainsAny(k+v, "\r\n\x00") {
					return
				}
				h.Set(k, v)
			}
			p.result <- wsResult{response: &http.Response{StatusCode: f.Status, Status: fmt.Sprintf("%d %s", f.Status, http.StatusText(f.Status)), Header: h, Body: &wsBody{call: p, conn: c}, ContentLength: -1}}
		case "data":
			if !p.headers || len(f.Data) > 32768 {
				return
			}
			select {
			case p.chunks <- f.Data:
			default:
				p.finish(errors.New("agyp response consumer too slow; request was not replayed"))
				c.remove(p.id)
				// Never block all streams behind a stalled consumer.
				go c.send(wsFrame{Type: "cancel", ID: p.id})
			}
		case "end":
			if !p.headers {
				return
			}
			p.finish(nil)
			c.remove(p.id)
		case "error":
			p.finish(errWSInterrupted)
			c.remove(p.id)
		default:
			return
		}
	}
}

type wsBody struct {
	call *wsCall
	conn *wsConn
	buf  []byte
}

func (b *wsBody) Read(out []byte) (int, error) {
	if len(out) == 0 {
		return 0, nil
	}
	for len(b.buf) == 0 {
		// Drain all already received bytes before surfacing EOF or interruption.
		select {
		case b.buf = <-b.call.chunks:
			continue
		default:
		}
		select {
		case b.buf = <-b.call.chunks:
		case <-b.call.done:
			select {
			case b.buf = <-b.call.chunks:
				continue
			default:
			}
			if err := b.call.failure(); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
	}
	n := copy(out, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}
func (b *wsBody) Close() error {
	b.call.finish(errors.New("response closed"))
	b.conn.remove(b.call.id)
	// A bounded write timeout keeps a vanished peer from leaking this goroutine.
	go b.conn.send(wsFrame{Type: "cancel", ID: b.call.id})
	return nil
}

// wsTransport maintains one authenticated connection. Only new requests reconnect;
// no frame from a failed connection is replayed, even before response headers.
type wsTransport struct {
	base       *url.URL
	key, keyID string
	mu         sync.Mutex
	conn       *wsConn
	closed     bool
	fallback   http.RoundTripper
}

func newWSTransport(base *url.URL, key string) (*wsTransport, error) {
	m := keyPattern.FindStringSubmatch(key)
	if m == nil {
		return nil, errors.New("invalid agyp key")
	}
	u, e := parseBase(base.String())
	if e != nil {
		return nil, e
	}
	return &wsTransport{base: u, key: key, keyID: m[1], fallback: client().Transport}, nil
}
func (t *wsTransport) connection(ctx context.Context) (*wsConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("agyp transport closed")
	}
	if t.conn != nil {
		t.conn.mu.Lock()
		dead := t.conn.dead
		t.conn.mu.Unlock()
		if !dead {
			return t.conn, nil
		}
	}
	u := *t.base
	u.Path = strings.TrimRight(u.Path, "/") + "/transport"
	u.RawPath = ""
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	d := websocket.Dialer{HandshakeTimeout: 10 * time.Second, Subprotocols: []string{"agyp.v1"}, Proxy: nil, EnableCompression: false}
	conn, resp, e := d.DialContext(ctx, u.String(), nil)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if e != nil {
		return nil, errors.New("agyp websocket connection failed")
	}
	stopAuthCancel := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopAuthCancel()
	good := false
	defer func() {
		if !good {
			conn.Close()
		}
	}()
	conn.SetReadLimit(65536)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if conn.Subprotocol() != "agyp.v1" {
		return nil, errors.New("invalid agyp websocket protocol")
	}
	var challenge wsFrame
	if conn.ReadJSON(&challenge) != nil || challenge.Type != "challenge" || len(challenge.Nonce) != 43 || len(challenge.Salt) != 43 || !noncePattern.MatchString(challenge.Nonce) || !noncePattern.MatchString(challenge.Salt) || challenge.Expires <= time.Now().UnixMilli() {
		return nil, errors.New("invalid agyp websocket challenge")
	}
	mac := hmac.New(sha256.New, []byte(t.key))
	mac.Write([]byte("agyp-ws-v1\n" + challenge.Salt + "\n" + challenge.Nonce))
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if conn.WriteJSON(wsFrame{Type: "auth", KeyID: t.keyID, Proof: hex.EncodeToString(mac.Sum(nil))}) != nil {
		return nil, errors.New("agyp websocket authentication failed")
	}
	var ready wsFrame
	if conn.ReadJSON(&ready) != nil || ready.Type != "ready" {
		return nil, errors.New("agyp websocket authentication failed")
	}
	conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	conn.SetPingHandler(func(data string) error {
		conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(10*time.Second))
	})
	c := &wsConn{socket: conn, calls: map[string]*wsCall{}}
	t.conn = c
	good = true
	go c.read()
	return c, nil
}
func (t *wsTransport) Connect(ctx context.Context) error { _, e := t.connection(ctx); return e }
func (t *wsTransport) Close() error {
	t.mu.Lock()
	t.closed = true
	c := t.conn
	t.mu.Unlock()
	if c != nil {
		c.fail()
	}
	return nil
}
func (t *wsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != t.base.Scheme || req.URL.Host != t.base.Host {
		return t.fallback.RoundTrip(req)
	}
	path := strings.TrimPrefix(req.URL.EscapedPath(), strings.TrimRight(t.base.Path, "/"))
	if (!inferenceAllowed(req.Method, path) && !(req.Method == "POST" && path == "/v1internal:loadCodeAssist" && req.URL.RawQuery == "")) || req.URL.RawPath != "" {
		return nil, errors.New("agyp websocket endpoint forbidden")
	}
	if req.URL.RawQuery != "" || req.URL.ForceQuery {
		path += "?" + req.URL.RawQuery
	}
	c, e := t.connection(req.Context())
	if e != nil {
		return nil, e
	}
	rid := make([]byte, 16)
	if _, e = rand.Read(rid); e != nil {
		return nil, e
	}
	p := &wsCall{id: hex.EncodeToString(rid), result: make(chan wsResult, 1), chunks: make(chan []byte, 16), done: make(chan struct{})}
	c.mu.Lock()
	if c.dead || len(c.calls) >= 8 {
		c.mu.Unlock()
		return nil, errors.New("agyp websocket concurrency limit or closed connection")
	}
	c.calls[p.id] = p
	c.mu.Unlock()
	deadline := time.Now().Add(599 * time.Second)
	if d, ok := req.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	h := req.Header.Clone()
	clean(h)
	for _, name := range []string{"Authorization", "Cookie", "X-Goog-Api-Key", "Proxy-Authorization", "Content-Length"} {
		h.Del(name)
	}
	hs := map[string]string{}
	for k, v := range h {
		hs[k] = strings.Join(v, ", ")
	}
	var uploadMu sync.Mutex
	var cancelOnce sync.Once
	cancel := func() {
		cancelOnce.Do(func() {
			p.finish(errWSInterrupted)
			c.remove(p.id)
			if req.Body != nil {
				req.Body.Close()
			}
			go func() { uploadMu.Lock(); defer uploadMu.Unlock(); c.send(wsFrame{Type: "cancel", ID: p.id}) }()
		})
	}
	sendUpload := func(f wsFrame) error {
		uploadMu.Lock()
		defer uploadMu.Unlock()
		select {
		case <-p.done:
			return errWSInterrupted
		default:
		}
		return c.send(f)
	}
	// From this first write onward, all failures are ambiguous and MUST NOT retry.
	if e = c.send(wsFrame{Type: "start", ID: p.id, Method: req.Method, Path: path, Headers: hs, Deadline: deadline.UnixMilli()}); e != nil {
		cancel()
		return nil, e
	}
	go func() {
		select {
		case <-req.Context().Done():
			cancel()
		case <-p.done:
			if req.Body != nil {
				req.Body.Close()
			}
		}
	}()
	if req.Body != nil {
		defer req.Body.Close()
		buf := make([]byte, 32768)
		total := 0
		for {
			n, err := req.Body.Read(buf)
			total += n
			if total > 16*1024*1024 {
				cancel()
				return nil, errors.New("agyp request exceeds 16 MiB")
			}
			if n > 0 {
				if e = sendUpload(wsFrame{Type: "data", ID: p.id, Data: buf[:n]}); e != nil {
					cancel()
					return nil, e
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				cancel()
				return nil, errors.New("agyp request body read failed")
			}
		}
	}
	if e = sendUpload(wsFrame{Type: "end", ID: p.id}); e != nil {
		cancel()
		return nil, e
	}
	select {
	case result := <-p.result:
		result.response.Request = req
		return result.response, result.err
	case <-p.done:
		select {
		case result := <-p.result:
			result.response.Request = req
			return result.response, result.err
		default:
		}
		if err := p.failure(); err != nil {
			return nil, err
		}
		return nil, errWSInterrupted
	case <-req.Context().Done():
		cancel()
		return nil, req.Context().Err()
	}
}

// Keep the wire representation checked by encoding/json in both client and tests.
var _ http.RoundTripper = (*wsTransport)(nil)
