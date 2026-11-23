// WebSocket credential translation. When the front-side API key and the
// actor key differ, terminal and agent WebSocket upgrades cannot ride
// httputil.ReverseProxy: they authenticate inside their first JSON frame
// ({"type":"auth","token":...}), and the 101 response carries the whole
// connection from then on. spliceWS hijacks the client connection, performs
// the upgrade against the actor itself, rewrites the token in the first auth
// frame, then mirrors frames in both directions byte-for-byte.
package facade

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/viveksupe/Trident/internal/pool"
)

// isWebSocketUpgrade reports a WebSocket upgrade request.
func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// spliceWS performs the upgrade + token rewrite + frame mirror. It returns a
// non-zero bool when it took over the connection (success), and false on an
// unrecoverable setup error — handled before the hijack point, so the caller
// can still answer through the normal ResponseWriter.
func (s *Server) spliceWS(w http.ResponseWriter, r *http.Request, ready pool.Ready) bool {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return false
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		return false
	}
	defer clientConn.Close()

	ctx := context.Background()
	if err != nil {
		return false
	}
	defer clientConn.Close()

	actorConn, err := ready.Dialer.DialConn(ctx, "tcp")
	if err != nil {
		// Connection died before hijack effects reach Open WebUI; answer 503.
		writeJSON(w, http.StatusBadGateway, detail{"actor connection failed"})
		return false
	}
	defer actorConn.Close()

	actorBuf := bufio.NewReader(actorConn)

	// Build the upgrade request the actor sees: same path + WS headers, but
	// the actor API key instead of the front-side key.
	var req strings.Builder
	fmt.Fprintf(&req, "%s %s HTTP/1.1\r\n", r.Method, r.URL.RequestURI())
	req.WriteString("Connection: Upgrade\r\nUpgrade: websocket\r\n")
	fmt.Fprintf(&req, "Host: %s\r\n", r.Host)
	for k, vs := range r.Header {
		switch normalHeader(k) {
		case "Authorization", "Connection", "Upgrade", "Sec-Websocket-Key",
			"Sec-Websocket-Version": // set below or rewritten
		default:
			for _, v := range vs {
				fmt.Fprintf(&req, "%s: %s\r\n", k, v)
			}
		}
	}
	fmt.Fprintf(&req, "Sec-Websocket-Key: %s\r\n", defaultIfEmpty(r.Header.Get("Sec-Websocket-Key"),
		"dGhlIHNhbXBsZSBub25jZQ=="))
	req.WriteString("Sec-Websocket-Version: 13\r\n")
	fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", s.cfg.ActorAPIKey)
	req.WriteString("\r\n")

	if _, err := actorConn.Write([]byte(req.String())); err != nil {
		writeJSON(w, http.StatusBadGateway, detail{"actor connection failed"})
		return false
	}

	resp, err := http.ReadResponse(actorBuf, r)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		writeJSON(w, http.StatusBadGateway, detail{"actor refused the terminal upgrade"})
		return false
	}

	// Mirror the 101 (status line + WS response headers: Sec-WebSocket-Accept,
	// protocol, extensions) verbatim, then splice.
	var out strings.Builder
	fmt.Fprintf(&out, "HTTP/1.1 101 Switching Protocols\r\n")
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&out, "%s: %s\r\n", k, v)
		}
	}
	out.WriteString("\r\n")
	if _, err := clientConn.Write([]byte(out.String())); err != nil {
		return false
	}

	// Frames the client already had in flight beyond the upgrade request ride
	// clientBuf; splice them through the same path so an early auth frame is
	// still rewritten.
	s.mirrorFrames(clientBuf.Reader, clientConn, actorBuf, actorConn)
	return true
}

// mirrorFrames rewrites the first client auth frame, then mirrors both
// directions until either side closes. Whichever direction finishes closes
// BOTH connections so the other side's blocked read unblocks, and the call
// returns only after both directions have ended: spliceWS must never outlive
// either socket, because routeNoAuth releases its inflight refcount only when
// spliceWS returns (a one-directional teardown — a client dying while the
// actor stays silent — pins the pool session forever: the sweep skips
// sessions with inflight > 0).
func (s *Server) mirrorFrames(clientBuf *bufio.Reader, clientConn net.Conn, actorBuf *bufio.Reader, actorConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	// Client → actor with first-frame rewrite, bounded scan: the protocol
	// places the auth frame first; a hostile client sending non-auth frames
	// still gets through after this loop gives up rewriting.
	go func() {
		defer wg.Done()
		// A dead client tears the session down from here: without these
		// closes the actor→client copy below stays blocked on a silent actor
		// and leaks the goroutine, both fds and the inflight refcount.
		defer actorConn.Close()
		defer clientConn.Close()
		for i := 0; i < 8; i++ {
			f, err := readWSFrame(clientBuf)
			if err != nil {
				var big oversizeFrame
				if errors.As(err, &big) {
					// Not the auth frame (that is a small JSON object):
					// replay every header byte consumed so far and let the
					// raw splice below carry the payload — it is never
					// buffered, so the client-declared 64-bit length can
					// neither OOM nor panic the process.
					if _, werr := actorConn.Write(big.raw); werr != nil {
						return
					}
					break
				}
				// EOF or RFC 6455 violation (control frames carry at most
				// 125 bytes): drop the connection — the teardown closes
				// both sides.
				return
			}
			if f.opcode == 0x1 && isAuthFrame(f.payload) {
				if rewritten, ok := rewriteAuthToken(f.payload, s.cfg.ActorAPIKey); ok {
					f.payload = rewritten
				}
				if err := writeMaskedFrame(actorConn, f.head, f.payload); err != nil {
					return
				}
				break
			}
			if err := writeMaskedFrame(actorConn, f.head, f.payload); err != nil {
				return
			}
		}
		// Raw splice for everything after the (rewritten) auth frame.
		_, _ = io.Copy(actorConn, bufioFirstThen{r: clientBuf, c: clientConn})
	}()
	// Actor → client: any buffered bytes first (the 101 was read through
	// actorBuf), then raw copy. Its exit closes both conns too, so a finished
	// actor never strands the client→actor reader.
	go func() {
		defer wg.Done()
		defer actorConn.Close()
		defer clientConn.Close()
		_, _ = io.Copy(clientConn, bufioFirstThen{r: actorBuf, c: actorConn})
	}()
	// Every exit path above closed both connections, which unblocks the peer
	// direction — so this wait can only end with neither socket in use.
	wg.Wait()
}

// bufioFirstThen reads the bufio.Reader to exhaustion, then the raw conn.
type bufioFirstThen struct {
	r *bufio.Reader
	c net.Conn
}

func (b bufioFirstThen) Read(p []byte) (int, error) {
	if n := b.r.Buffered(); n > 0 {
		return b.r.Read(p)
	}
	return b.c.Read(p)
}

func normalHeader(k string) string {
	return http.CanonicalHeaderKey(k)
}

func defaultIfEmpty(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// wsFrame is one fully-read WebSocket frame (payload unmasked).
type wsFrame struct {
	head    byte // FIN/RSV/opcode byte, forwarded verbatim
	opcode  byte
	payload []byte
}

// maxScanPayload bounds what the pre-auth frame scan will buffer. The auth
// frame is a few hundred bytes of JSON; the length field it would otherwise
// allocate from is a client-controlled 64-bit value, and readWSFrame runs in
// a goroutine that net/http does not recover — a huge make([]byte, ln) would
// OOM or panic the whole process, and several small frames could smuggle
// gigabytes through the unconstrained budget first.
const maxScanPayload = 64 << 10

// errControlPayload reports an RFC 6455 violation: control frames (opcode
// >= 0x8, e.g. ping/close) must carry at most 125 bytes. The splice drops
// the connection when the scan sees one.
var errControlPayload = errors.New("ws: control frame payload exceeds 125 bytes")

// errInvalidLength reports a 64-bit length whose reserved most-significant
// bit is set (RFC 6455 forbids it). As int64 such a value decodes negative,
// slipping past every upper-bound check straight into make([]byte, ln) — an
// attacker-controlled process kill. The connection is dropped.
var errInvalidLength = errors.New("ws: frame length sets the reserved most-significant bit")

// oversizeFrame reports a data frame whose declared payload exceeds
// maxScanPayload. raw holds every header byte consumed so far — head,
// extended length and mask key — for byte-exact replay before the raw splice
// resumes; the payload itself is streamed, never buffered.
type oversizeFrame struct {
	raw []byte
	ln  int64
}

func (e oversizeFrame) Error() string {
	return fmt.Sprintf("ws: declared payload %d exceeds the %d-byte scan cap", e.ln, maxScanPayload)
}

// readWSFrame reads one frame header (and, within the scan cap, its payload)
// from r. Control frames obey RFC 6455's 125-byte rule — violations return
// errControlPayload so the caller drops the connection. Oversized data frames
// return oversizeFrame carrying the consumed header bytes instead of ever
// allocating from a client-declared 64-bit length; the shim speaks no
// extensions.
func readWSFrame(r *bufio.Reader) (wsFrame, error) {
	var consumed bytes.Buffer
	head, err := r.ReadByte()
	if err != nil {
		return wsFrame{}, err
	}
	consumed.WriteByte(head)
	h2, err := r.ReadByte()
	if err != nil {
		return wsFrame{}, err
	}
	consumed.WriteByte(h2)
	opcode := head & 0x0f
	masked := h2&0x80 != 0
	ln := int64(h2 & 0x7f)
	switch ln {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return wsFrame{}, err
		}
		consumed.Write(b[:])
		ln = int64(b[0])<<8 | int64(b[1])
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return wsFrame{}, err
		}
		consumed.Write(b[:])
		ln = 0
		for _, c := range b {
			ln = ln<<8 | int64(c)
		}
	}
	if ln < 0 {
		return wsFrame{}, errInvalidLength
	}
	if opcode&0x8 != 0 && ln > 125 {
		return wsFrame{}, errControlPayload
	}
	mask := [4]byte{}
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return wsFrame{}, err
		}
		consumed.Write(mask[:])
	}
	if ln > maxScanPayload {
		return wsFrame{}, oversizeFrame{raw: consumed.Bytes(), ln: ln}
	}
	payload := make([]byte, ln)
	if _, err := io.ReadFull(r, payload); err != nil {
		return wsFrame{}, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return wsFrame{head: head, opcode: opcode, payload: payload}, nil
}

// writeMaskedFrame writes a frame with a fresh client mask (the actor side
// expects masked client frames).
func writeMaskedFrame(w io.Writer, head byte, payload []byte) error {
	var hdr [14]byte
	n := 0
	hdr[0] = head
	n = 1
	mask := [4]byte{0x51, 0x88, 0x2B, 0xEF}
	l := len(payload)
	masked := head&0x80 != 0
	switch {
	case l < 126:
		if masked {
			hdr[n] = 0x80 | byte(l)
		} else {
			hdr[n] = byte(l)
		}
		n++
	case l < 65536:
		if masked {
			hdr[n] = 0x80 | 126
		} else {
			hdr[n] = 126
		}
		n++
		hdr[n] = byte(l >> 8)
		hdr[n+1] = byte(l)
		n += 2
	default:
		if masked {
			hdr[n] = 0x80 | 127
		} else {
			hdr[n] = 127
		}
		n++
		v := uint64(l)
		for i := 7; i >= 0; i-- {
			hdr[n] = byte(v >> (8 * i))
			n++
		}
	}
	if masked {
		copy(hdr[n:], mask[:])
		n += 4
	}
	// Mask into a scratch buffer: payload may be modified in place; write a
	// copy so retry-after-error stays consistent.
	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i]
	}
	if masked {
		for i := range maskedPayload {
			maskedPayload[i] ^= mask[i%4]
		}
	}
	if _, err := w.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := w.Write(maskedPayload)
	return err
}

// wsAuthFrame is the subset of the first frame the shim rewrites.
type wsAuthFrame struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}

func isAuthFrame(payload []byte) bool {
	var f wsAuthFrame
	return json.Unmarshal(payload, &f) == nil && f.Type == "auth"
}

// rewriteAuthToken replaces ONLY the token field of an auth frame, mapping
// the JSON object so every other field survives verbatim (Open WebUI's auth
// frames carry cursor, resume, flow_control, chat_id… — the agent protocol
// aborts turns on cursor gaps, so a {type,token}-only re-marshal would break
// them even though authentication itself passes).
func rewriteAuthToken(payload []byte, token string) ([]byte, bool) {
	var f map[string]any
	if json.Unmarshal(payload, &f) != nil || f["type"] != "auth" {
		return nil, false
	}
	f["token"] = token
	out, err := json.Marshal(f)
	if err != nil {
		return nil, false
	}
	return out, true
}
