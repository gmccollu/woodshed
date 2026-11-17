// Package loadgen is Woodshed's test tooling, behind `woodshed send` and
// `woodshed bench`. Send sends numbered syslog messages to any syslog server
// (or numbered SNMP traps and informs to any trap receiver, Proto "trap");
// Bench runs an in-process Woodshed pipeline (listener, store, live hub) in a temp
// data dir, sends to it at a target rate, and then checks on disk that every
// message arrived exactly once.
package loadgen

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults for SendOptions.
const (
	DefaultSize     = 200
	DefaultHostname = "woodshed-send"
)

// SendOptions configures Send.
type SendOptions struct {
	Addr    string // host:port of the syslog server (or trap receiver)
	Proto   string // "udp" (default), "tcp", "tls" (syslog over TLS, RFC 5425) or "trap" (SNMP, UDP)
	Framing string // TCP and TLS: "lf" (newline, default) or "octet" (RFC 6587 octet counting)
	// TLS is the client configuration for Proto "tls" (ClientTLSConfig makes
	// one). Required for "tls".
	TLS *tls.Config

	// Count messages are sent. With Count 0, Rate × Duration are.
	Count    int
	Rate     float64       // messages per second; 0 sends as fast as possible
	Duration time.Duration // used when Count is 0 (needs a Rate)

	Size     int    // approximate message size in bytes, padded (default 200)
	RunID    string // tag carried in every message (default random)
	FirstSeq int    // sequence number of the first message (default 0)
	Hostname string // the message's HOSTNAME field (default "woodshed-send")

	// Message, if set, replaces the padding: each message is the sequence tag and
	// number, a space and Message, and Size is ignored. It can't contain CR, LF or
	// NUL (they would split the message under newline framing).
	Message string
	// Source is the local IP address to send from (for example 127.0.0.2, to test
	// several senders from one machine). Empty lets the OS choose.
	Source string

	// Trap configures Proto "trap": each trap or inform carries SeqTag(RunID) and
	// its sequence number in the SeqOID varbind. Size and Hostname don't apply;
	// Message is appended to the sequence varbind.
	Trap TrapOptions
}

// SendResult describes a Send.
type SendResult struct {
	RunID   string
	Sent    int // messages the OS accepted
	Elapsed time.Duration
	Rate    float64 // achieved messages per second
	// Backpressure counts sends the OS refused for lack of buffer space (UDP
	// ENOBUFS) and that were retried; no message is skipped for it.
	Backpressure int
	// Refused is the refusals (ICMP port unreachable) after the receiver had
	// been listening; each datagram was sent again (RefusedGrace).
	Refused Refusals
	// Informs holds the Responses' results for Proto "trap" with Trap.Inform.
	Informs *InformStats
}

// NewRunID returns a random 8-hex-digit run tag.
func NewRunID() string {
	var b [4]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// SeqTag returns the marker every message of a run carries, followed by the
// sequence number: "seq=<run>:". The number ends at the first non-digit (a
// space in syslog, the closing quote of a trap's str varbind).
func SeqTag(runID string) string { return "seq=" + runID + ":" }

// message appends one RFC 5424 message (without framing) for seq.
func message(dst []byte, o *SendOptions, seq int, now time.Time) []byte {
	start := len(dst)
	dst = append(dst, "<134>1 "...)
	dst = now.UTC().AppendFormat(dst, "2006-01-02T15:04:05.000Z")
	dst = append(dst, ' ')
	dst = append(dst, o.Hostname...)
	dst = append(dst, " woodshed - - - "...)
	dst = append(dst, SeqTag(o.RunID)...)
	dst = strconv.AppendInt(dst, int64(seq), 10)
	if o.Message != "" {
		dst = append(dst, ' ')
		return append(dst, o.Message...)
	}
	if pad := o.Size - (len(dst) - start) - 1; pad > 0 {
		dst = append(dst, ' ')
		for i := 0; i < pad; i++ {
			dst = append(dst, byte('a'+(seq+i)%26))
		}
	}
	return dst
}

func (o *SendOptions) defaults() error {
	if o.Addr == "" {
		return errors.New("loadgen: Addr is required")
	}
	switch o.Proto {
	case "":
		o.Proto = "udp"
	case "udp", "tcp":
	case "trap":
		if err := o.Trap.defaults(); err != nil {
			return err
		}
	case "tls":
		if o.TLS == nil {
			return errors.New("loadgen: TLS needs a CA certificate to trust (or insecure)")
		}
	default:
		return fmt.Errorf("loadgen: unknown protocol %q (udp, tcp, tls or trap)", o.Proto)
	}
	switch o.Framing {
	case "":
		o.Framing = "lf"
	case "lf", "octet":
	default:
		return fmt.Errorf("loadgen: unknown framing %q (lf or octet)", o.Framing)
	}
	if o.Count <= 0 {
		if o.Rate <= 0 || o.Duration <= 0 {
			return errors.New("loadgen: give Count, or Rate and Duration")
		}
		o.Count = int(o.Rate * o.Duration.Seconds())
	}
	if o.Size <= 0 {
		o.Size = DefaultSize
	}
	if o.RunID == "" {
		o.RunID = NewRunID()
	}
	if strings.ContainsAny(o.RunID, " :\n\r") {
		return fmt.Errorf("loadgen: RunID %q has a space or ':'", o.RunID)
	}
	if o.Hostname == "" {
		o.Hostname = DefaultHostname
	}
	if strings.ContainsAny(o.Message, "\r\n\x00") {
		return errors.New("loadgen: Message can't contain CR, LF or NUL")
	}
	if o.Source != "" {
		if _, err := netip.ParseAddr(o.Source); err != nil {
			return fmt.Errorf("loadgen: Source %q is not an IP address", o.Source)
		}
	}
	return nil
}

// dialer returns a dialer bound to o.Source, if set.
func (o *SendOptions) dialer(proto string) net.Dialer {
	var d net.Dialer
	if o.Source != "" {
		ip := net.IP(netip.MustParseAddr(o.Source).AsSlice())
		if proto == "udp" {
			d.LocalAddr = &net.UDPAddr{IP: ip}
		} else {
			d.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}
	return d
}

// pacer spreads sends evenly at a rate: due returns how many messages should have
// gone out by now.
type pacer struct {
	start time.Time
	rate  float64
}

func (p pacer) due(n int) int {
	if p.rate <= 0 {
		return n
	}
	return min(n, int(time.Since(p.start).Seconds()*p.rate)+1)
}

// wait sleeps until the next message is due (a millisecond at most, so sends go out
// in small, frequent batches).
func (p pacer) wait(ctx context.Context, sent int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.rate <= 0 {
		return nil
	}
	next := p.start.Add(time.Duration(float64(sent) / p.rate * float64(time.Second)))
	if d := time.Until(next); d > 0 {
		time.Sleep(min(d, time.Millisecond))
	}
	return nil
}

// Send sends o.Count numbered messages (or o.Rate × o.Duration) to o.Addr. Each
// message carries SeqTag(RunID) and its sequence number. It stops early, with
// what was sent so far, if ctx is cancelled or the connection fails.
func Send(ctx context.Context, o SendOptions) (SendResult, error) {
	if err := o.defaults(); err != nil {
		return SendResult{}, err
	}
	res := SendResult{RunID: o.RunID}
	var err error
	start := time.Now()
	switch o.Proto {
	case "udp":
		err = sendUDP(ctx, &o, &res)
	case "trap":
		err = sendTrap(ctx, &o, &res)
	default:
		err = sendTCP(ctx, &o, &res)
	}
	res.Elapsed = time.Since(start)
	if s := res.Elapsed.Seconds(); s > 0 {
		res.Rate = float64(res.Sent) / s
	}
	return res, err
}

func sendUDP(ctx context.Context, o *SendOptions, res *SendResult) error {
	d := o.dialer("udp")
	c, err := d.DialContext(ctx, "udp", o.Addr)
	if err != nil {
		return fmt.Errorf("loadgen: %w", err)
	}
	defer c.Close()
	p := pacer{start: time.Now(), rate: o.Rate}
	buf := make([]byte, 0, o.Size+128)
	var ref refusals
	defer func() { res.Refused = ref.result() }()
	for res.Sent < o.Count {
		for due := p.due(o.Count); res.Sent < due; {
			buf = message(buf[:0], o, o.FirstSeq+res.Sent, time.Now())
			_, err := c.Write(buf)
			if err != nil {
				if isNoBufs(err) {
					// The OS send queue is full (macOS returns ENOBUFS for UDP rather
					// than blocking). Back off briefly and resend the same message.
					res.Backpressure++
					time.Sleep(50 * time.Microsecond)
					if ctx.Err() != nil {
						return ctx.Err()
					}
					continue
				}
				if isConnRefused(err) {
					// ICMP port unreachable from an earlier datagram: fatal while
					// nothing has ever answered; later, a restart: count it and
					// send this message again.
					if ref.refused(time.Now()) {
						return notListening(o.Addr)
					}
					if ctx.Err() != nil {
						return ctx.Err()
					}
					continue
				}
				return fmt.Errorf("loadgen: %w", err)
			}
			ref.wrote(time.Now())
			res.Sent++
		}
		if err := p.wait(ctx, res.Sent); err != nil {
			return err
		}
	}
	return nil
}

func sendTCP(ctx context.Context, o *SendOptions, res *SendResult) error {
	d := o.dialer("tcp")
	c, err := d.DialContext(ctx, "tcp", o.Addr)
	if err != nil {
		return fmt.Errorf("loadgen: %w", err)
	}
	defer c.Close()
	if o.Proto == "tls" {
		cfg := o.TLS.Clone()
		if cfg.ServerName == "" {
			if host, _, err := net.SplitHostPort(o.Addr); err == nil {
				cfg.ServerName = host
			}
		}
		tc := tls.Client(c, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("loadgen: TLS handshake with %s: %w", o.Addr, err)
		}
		defer tc.Close() // close_notify, then the connection
		c = tc
	}
	bw := bufio.NewWriterSize(c, 64<<10)
	p := pacer{start: time.Now(), rate: o.Rate}
	msg := make([]byte, 0, o.Size+128)
	pending := 0
	for res.Sent+pending < o.Count {
		for due := p.due(o.Count); res.Sent+pending < due; pending++ {
			msg = message(msg[:0], o, o.FirstSeq+res.Sent+pending, time.Now())
			if o.Framing == "octet" {
				bw.WriteString(strconv.Itoa(len(msg)))
				bw.WriteByte(' ')
				bw.Write(msg)
			} else {
				bw.Write(msg)
				bw.WriteByte('\n')
			}
			if bw.Available() < o.Size+128 {
				if err := bw.Flush(); err != nil {
					return fmt.Errorf("loadgen: %w", err)
				}
			}
		}
		if err := bw.Flush(); err != nil {
			return fmt.Errorf("loadgen: %w", err)
		}
		res.Sent += pending
		pending = 0
		if err := p.wait(ctx, res.Sent); err != nil {
			return err
		}
	}
	return nil
}

// ClientTLSConfig is a TLS client configuration for sending: it trusts the CA
// certificate in caFile (PEM or DER) and checks serverName (the address's host
// when empty), or with insecure checks nothing (for a quick test only).
func ClientTLSConfig(caFile, serverName string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	if insecure {
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}
	if caFile == "" {
		return nil, errors.New("loadgen: TLS needs --ca FILE (the CA certificate to trust), or --insecure")
	}
	b, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("loadgen: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, fmt.Errorf("loadgen: %s holds no PEM or DER certificate", caFile)
		}
		pool.AddCert(c)
	}
	cfg.RootCAs = pool
	return cfg, nil
}
