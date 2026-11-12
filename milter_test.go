package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-milter"
	"github.com/ryroniq/go-msgauth/dkim"
)

// A message as it appears on the wire, with odd but legal header spacing.
const wireMsg = "From: Alice <alice@example.com>\r\n" +
	"To:  Bob <bob@example.org>\r\n" +
	"Subject:no space\r\n" +
	"Date: Wed, 11 Nov 2026 12:00:00 +0000\r\n" +
	"X-Folded: first\r\n" +
	"\tsecond\r\n" +
	"\r\n" +
	"Hello Bob.\r\n" +
	".leading dot\r\n"

// split mimics how Postfix hands headers to a milter: name/value pairs with
// folding as bare LF, and the whitespace after the colon stripped unless
// SMFIP_HDR_LEADSPC is in effect.
func split(t *testing.T, raw string, leadSpace bool) (hdrs []field, body string) {
	t.Helper()
	head, body, ok := strings.Cut(raw, "\r\n\r\n")
	if !ok {
		t.Fatal("no header/body separator")
	}
	for _, line := range strings.Split(head, "\r\n") {
		if line[0] == ' ' || line[0] == '\t' {
			hdrs[len(hdrs)-1].value += "\n" + line
			continue
		}
		name, value, _ := strings.Cut(line, ":")
		if !leadSpace {
			value = strings.TrimLeft(value, " \t")
		}
		hdrs = append(hdrs, field{name, value})
	}
	return hdrs, body
}

func rebuild(hdrs []field, body string) *message {
	var m message
	for _, h := range hdrs {
		m.addHeader(h.name, h.value)
	}
	m.endHeaders()
	m.addBody([]byte(body))
	return &m
}

func TestRawField(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		verbatim    bool
		want        string
	}{
		{"Subject", "hi", false, "Subject: hi\r\n"},
		{"Subject", "", false, "Subject: \r\n"},
		{"X", "a\n\tb", false, "X: a\r\n\tb\r\n"},
		{"X", "a\r\n b", false, "X: a\r\n b\r\n"},
		{"Subject", " hi", true, "Subject: hi\r\n"},
		{"Subject", "  hi", true, "Subject:  hi\r\n"},
		{"Subject", "hi", true, "Subject:hi\r\n"},
		{"Subject", "", true, "Subject:\r\n"},
	} {
		if got := rawField(tc.name, tc.value, tc.verbatim); got != tc.want {
			t.Errorf("rawField(%q, %q, %v) = %q, want %q", tc.name, tc.value, tc.verbatim, got, tc.want)
		}
	}
}

func TestBodyCRLFAcrossChunks(t *testing.T) {
	var m message
	m.addBody([]byte("a\r"))
	m.addBody([]byte("\nb\nc\r\n"))
	if got, want := m.buf.String(), "a\r\nb\r\nc\r\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

type testKey struct {
	priv ed25519.PrivateKey
	txt  string
}

func newTestKey(t *testing.T) testKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{priv, "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub)}
}

func (k testKey) lookup(domain string) ([]string, error) {
	if domain == "sel._domainkey.example.com" {
		return []string{k.txt}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
}

// The reconstructed message must verify a simple/simple signature made over
// the original wire bytes. That only holds byte-exact when the MTA keeps the
// leading space; without it, ordinary "Name: value" headers still work.
func TestSimpleCanonicalization(t *testing.T) {
	key := newTestKey(t)
	var signed bytes.Buffer
	err := dkim.Sign(&signed, strings.NewReader(wireMsg), &dkim.SignOptions{
		Domain: "example.com", Selector: "sel", Signer: key.priv,
		HeaderKeys: []string{"From", "To", "Subject", "Date", "X-Folded"},
	})
	if err != nil {
		t.Fatal(err)
	}

	hdrs, body := split(t, signed.String(), true)
	m := rebuild(hdrs, body)
	if m.buf.String() != signed.String() {
		t.Fatalf("reconstruction differs:\n%q\n%q", m.buf.String(), signed.String())
	}
	verifs, err := dkim.VerifyWithOptions(&m.buf, &dkim.VerifyOptions{LookupTXT: key.lookup})
	if err != nil || len(verifs) != 1 || verifs[0].Err != nil {
		t.Fatalf("verify: %v %+v", err, verifs)
	}
}

func serve(t *testing.T, srv *milter.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "m.sock")
	ln, err := listen(path)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return path
}

type envelope struct {
	ip, helo, from string
}

// send runs one message through a milter session and returns its actions.
func send(t *testing.T, s *milter.ClientSession, env envelope, raw string, leadSpace bool) []milter.ModifyAction {
	t.Helper()
	if _, err := s.Mail(env.from, nil); err != nil {
		t.Fatal(err)
	}
	hdrs, body := split(t, raw, leadSpace)
	for _, h := range hdrs {
		if _, err := s.HeaderField(h.name, h.value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.HeaderEnd(); err != nil {
		t.Fatal(err)
	}
	acts, act, err := s.BodyReadFrom(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if act.Code != milter.ActContinue && act.Code != milter.ActAccept {
		t.Fatalf("final action %c", act.Code)
	}
	return acts
}

// session connects to a milter. connMacros are sent with the connect stage,
// as Postfix sends milter_connect_macros.
func session(t *testing.T, path string, env envelope, connMacros ...string) *milter.ClientSession {
	t.Helper()
	// Restrict to actions protocol v2 knows, so the client accepts
	// go-milter's v2 reply (Postfix downgrades on its own).
	c := milter.NewClientWithOptions("unix", path, milter.ClientOptions{
		ActionMask: milter.OptAddHeader | milter.OptChangeHeader,
	})
	s, err := c.Session()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if len(connMacros) > 0 {
		if err := s.Macros(milter.CodeConn, connMacros...); err != nil {
			t.Fatal(err)
		}
	}
	if env.ip != "" {
		if _, err := s.Conn("mx.example.net", milter.FamilyInet, 25, env.ip); err != nil {
			t.Fatal(err)
		}
	} else if _, err := s.Conn("localhost", milter.FamilyUnknown, 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Helo(env.helo); err != nil {
		t.Fatal(err)
	}
	return s
}

func inserted(acts []milter.ModifyAction, name string) []string {
	var vs []string
	for _, a := range acts {
		if a.Code == milter.ActInsertHeader && strings.EqualFold(a.HeaderName, name) {
			vs = append(vs, a.HeaderValue)
		}
	}
	return vs
}

type stubResolver struct{}

func (stubResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if name == "example.com" {
		return []string{"v=spf1 ip4:192.0.2.1 -all"}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
func (stubResolver) LookupMX(context.Context, string) ([]*net.MX, error) { return nil, nil }
func (stubResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, nil
}
func (stubResolver) LookupAddr(context.Context, string) ([]string, error) { return nil, nil }

// deleted reports whether acts delete header name #idx.
func deleted(acts []milter.ModifyAction, name string, idx uint32) bool {
	for _, a := range acts {
		if a.Code == milter.ActChangeHeader && strings.EqualFold(a.HeaderName, name) && a.HeaderIndex == idx && a.HeaderValue == "" {
			return true
		}
	}
	return false
}

// Sign through the sign milter, then check the result through the verify
// milter: pass, authserv-id taken from Postfix's j macro, a forged
// Authentication-Results and an incoming junk header removed, tampering
// detected, and SPF still evaluated for the second message on the same
// connection.
func TestSignThenVerify(t *testing.T) {
	key := newTestKey(t)
	signingKeys = []signingKey{{signingEntry{Pattern: "@example.com", Domain: "example.com", Selector: "sel"}, key.priv}}
	dkimLookupTXT = key.lookup
	spfOptions = []spf.Option{spf.WithResolver(stubResolver{})}
	authservName = "fallback.test"
	wantID := "mx.test" // sent as macro j
	if authservID != "" {
		authservName, wantID = authservID, authservID
	}
	junk := junkHeader
	if junk == "" {
		junk = "X-Spam" // only checked when enabled
	}

	for _, leadSpace := range []bool{false, true} {
		signPath := serve(t, &milter.Server{
			NewMilter: func() milter.Milter { return &signSession{} },
			Actions:   milter.OptAddHeader,
			Protocol:  milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo,
		})
		verifyPath := serve(t, &milter.Server{
			NewMilter: func() milter.Milter { return &verifySession{} },
			Actions:   milter.OptAddHeader | milter.OptChangeHeader,
			Protocol:  milter.OptNoRcptTo,
		})

		ss := session(t, signPath, envelope{})
		acts := send(t, ss, envelope{from: "alice@example.com"}, wireMsg, leadSpace)
		sigs := inserted(acts, "DKIM-Signature")
		if len(sigs) != 1 {
			t.Fatalf("leadSpace=%v: want 1 signature, got %+v", leadSpace, acts)
		}
		if strings.Contains(sigs[0], "\r") {
			t.Errorf("leadSpace=%v: signature folded with CR: %q", leadSpace, sigs[0])
		}
		if leadSpace != strings.HasPrefix(sigs[0], " ") {
			t.Errorf("leadSpace=%v: signature value %q", leadSpace, sigs[0])
		}
		signed := rawField("DKIM-Signature", sigs[0], leadSpace) +
			"Authentication-Results: " + wantID + " 1; dkim=pass header.d=forged.example\r\n" +
			junk + ": yes\r\n" + wireMsg

		// Different sender domain: no signature.
		if acts := send(t, ss, envelope{from: "x@other.example"}, wireMsg, leadSpace); len(acts) != 0 {
			t.Errorf("unexpected actions for unmatched sender: %+v", acts)
		}

		env := envelope{ip: "192.0.2.1", helo: "mx.example.net", from: "alice@example.com"}
		vs := session(t, verifyPath, env, "j", "mx.test")
		acts = send(t, vs, env, signed, leadSpace)
		ar := inserted(acts, "Authentication-Results")
		if len(ar) != 1 || !strings.HasPrefix(strings.TrimSpace(ar[0]), wantID+";") ||
			!strings.Contains(ar[0], "dkim=pass header.d=example.com") || !strings.Contains(ar[0], "spf=pass") {
			t.Fatalf("leadSpace=%v: Authentication-Results %q", leadSpace, ar)
		}
		if strings.Contains(ar[0], "\r") {
			t.Errorf("leadSpace=%v: Authentication-Results folded with CR: %q", leadSpace, ar[0])
		}
		if junkHeader != "" {
			if len(inserted(acts, junkHeader)) != 0 {
				t.Errorf("leadSpace=%v: junk header on passing mail", leadSpace)
			}
			if !deleted(acts, junkHeader, 1) {
				t.Errorf("leadSpace=%v: incoming %s not removed: %+v", leadSpace, junkHeader, acts)
			}
		}
		if !deleted(acts, "Authentication-Results", 1) {
			t.Errorf("leadSpace=%v: forged Authentication-Results not removed: %+v", leadSpace, acts)
		}

		// Second message on the same connection, tampered body.
		tampered := strings.Replace(signed, "Hello Bob.", "Hello Eve.", 1)
		acts = send(t, vs, env, tampered, leadSpace)
		ar = inserted(acts, "Authentication-Results")
		if len(ar) != 1 || !strings.Contains(ar[0], "dkim=fail") || !strings.Contains(ar[0], "spf=pass") {
			t.Fatalf("leadSpace=%v: tampered Authentication-Results %q", leadSpace, ar)
		}
		if junkHeader != "" && len(inserted(acts, junkHeader)) != 1 {
			t.Errorf("leadSpace=%v: no junk header on failing mail", leadSpace)
		}
	}
}
