package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-milter"
	"github.com/ryroniq/go-msgauth/dkim"
)

const (
	spfTimeout        = 30 * time.Second
	dkimLookupTimeout = 10 * time.Second // per DKIM key lookup
	maxVerifications  = 5
)

// Overridable in tests.
var (
	spfOptions    []spf.Option
	dkimLookupTXT = lookupTXT
)

// lookupTXT is net.LookupTXT with a deadline. go-msgauth reports a timeout as
// temperror.
func lookupTXT(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dkimLookupTimeout)
	defer cancel()
	return net.DefaultResolver.LookupTXT(ctx, domain)
}

// authservName is the fallback authserv-id: authservID, or os.Hostname()
// when that is empty. Sessions prefer Postfix's $myhostname (see Connect).
var authservName string

func initAuthserv() error {
	authservName = authservID
	if authservName == "" {
		h, err := os.Hostname()
		if err != nil {
			return err
		}
		authservName = h
	}
	return nil
}

// spfResult and dkimResult keep the checked identities next to the verdict,
// which is what DMARC alignment needs later.
type spfResult struct {
	result   spf.Result
	ip       net.IP
	mailfrom string
	helo     string
	err      error
}

type dkimResult struct {
	result     string // pass, fail, permerror, temperror, none
	domain     string // d=
	identifier string // i=
	selector   string // s=
	err        error
}

type verifySession struct {
	milter.NoOpMilter
	authserv string // authserv-id for this connection
	ip       net.IP
	helo     string
	from     string
	msg      message

	authresIdx    int   // Authentication-Results headers seen so far
	forgedAuthres []int // 1-based indexes of ones claiming our authserv-id
	junkCount     int   // junkHeader headers seen; all are replaced
}

// Connect is the only callback that sees the connect macros: go-milter
// replaces the macro map on every macro packet.
func (s *verifySession) Connect(host, family string, port uint16, addr net.IP, m *milter.Modifier) (milter.Response, error) {
	s.authserv = authservName
	if j := m.Macros["j"]; authservID == "" && j != "" {
		s.authserv = j // $myhostname, in Postfix's default milter_connect_macros
	}
	if family == "tcp4" || family == "tcp6" {
		s.ip = addr
	}
	return milter.RespContinue, nil
}

func (s *verifySession) Helo(name string, m *milter.Modifier) (milter.Response, error) {
	s.helo = name
	return milter.RespContinue, nil
}

func (s *verifySession) MailFrom(from string, m *milter.Modifier) (milter.Response, error) {
	s.resetMessage()
	s.from = from
	return milter.RespContinue, nil
}

func (s *verifySession) Header(name, value string, m *milter.Modifier) (milter.Response, error) {
	s.msg.addHeader(name, value)
	switch {
	case strings.EqualFold(name, "Authentication-Results"):
		s.authresIdx++
		// authserv-id is the first token; an optional version may follow.
		id, _, _ := strings.Cut(value, ";")
		if f := strings.Fields(id); len(f) > 0 && strings.EqualFold(f[0], s.authserv) {
			s.forgedAuthres = append(s.forgedAuthres, s.authresIdx)
		}
	case junkHeader != "" && strings.EqualFold(name, junkHeader):
		s.junkCount++
	}
	return milter.RespContinue, nil
}

func (s *verifySession) Headers(_ textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	s.msg.endHeaders()
	return milter.RespContinue, nil
}

func (s *verifySession) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	s.msg.addBody(chunk)
	return milter.RespContinue, nil
}

func (s *verifySession) Abort(m *milter.Modifier) error {
	s.resetMessage()
	return nil
}

func (s *verifySession) resetMessage() {
	s.msg.reset()
	s.from = ""
	s.authresIdx = 0
	s.forgedAuthres = nil
	s.junkCount = 0
}

// Body runs at end of message. See signSession.Body for why it returns
// Continue.
func (s *verifySession) Body(m *milter.Modifier) (milter.Response, error) {
	defer s.resetMessage()
	qid := m.Macros["i"]

	spfRes := s.checkSPF()
	dkimRes := checkDKIM(s.msg.buf.Bytes(), qid)

	junk := false
	if spfRes != nil {
		log.Printf("%s: %s", qid, spfRes.format())
		junk = spfRes.result == spf.Fail || spfRes.result == spf.SoftFail
	}
	for _, r := range dkimRes {
		if r.result != "none" || debug {
			log.Printf("%s: %s", qid, r.format())
		}
		junk = junk || r.result == "fail" || r.result == "permerror"
	}

	// Delete from the last one so earlier indexes stay valid.
	for i := len(s.forgedAuthres) - 1; i >= 0; i-- {
		log.Printf("%s: removing Authentication-Results #%d claiming %s", qid, s.forgedAuthres[i], s.authserv)
		if err := m.ChangeHeader(s.forgedAuthres[i], "Authentication-Results", ""); err != nil {
			return nil, err
		}
	}
	// Our verdict replaces any junk header that came with the message.
	for i := s.junkCount; i > 0; i-- {
		if err := m.ChangeHeader(i, junkHeader, ""); err != nil {
			return nil, err
		}
	}
	if junk && junkHeader != "" {
		if err := m.InsertHeader(0, junkHeader, s.msg.headerValue("yes")); err != nil {
			return nil, err
		}
	}
	ar := formatAuthres(s.authserv, spfRes, dkimRes)
	if err := m.InsertHeader(0, "Authentication-Results", s.msg.headerValue(ar)); err != nil {
		return nil, err
	}
	return milter.RespContinue, nil
}

func (s *verifySession) checkSPF() *spfResult {
	if s.ip == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), spfTimeout)
	defer cancel()
	opts := append([]spf.Option{spf.WithContext(ctx)}, spfOptions...)
	r, err := spf.CheckHostWithSender(s.ip, s.helo, s.from, opts...)
	return &spfResult{result: r, ip: s.ip, mailfrom: s.from, helo: s.helo, err: err}
}

func checkDKIM(raw []byte, qid string) []dkimResult {
	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(raw), &dkim.VerifyOptions{
		LookupTXT:        dkimLookupTXT,
		MaxVerifications: maxVerifications,
	})
	if err != nil && err != dkim.ErrTooManySignatures {
		log.Printf("%s: dkim: %v", qid, err)
		return []dkimResult{{result: "permerror", err: err}}
	}
	if len(verifs) == 0 {
		return []dkimResult{{result: "none"}}
	}
	res := make([]dkimResult, 0, len(verifs))
	for _, v := range verifs {
		r := dkimResult{domain: v.Domain, identifier: v.Identifier, selector: v.Selector, err: v.Err}
		switch {
		case v.Err == nil:
			r.result = "pass"
		case dkim.IsTempFail(v.Err):
			r.result = "temperror"
		case dkim.IsPermFail(v.Err):
			r.result = "permerror"
		default:
			r.result = "fail"
		}
		res = append(res, r)
	}
	return res
}

// formatAuthres builds an RFC 8601 Authentication-Results value, one result
// per line, folded with bare LF as the milter protocol expects.
func formatAuthres(id string, spfRes *spfResult, dkimRes []dkimResult) string {
	parts := []string{id}
	if spfRes != nil {
		parts = append(parts, spfRes.format())
	}
	for _, r := range dkimRes {
		parts = append(parts, r.format())
	}
	return strings.Join(parts, ";\n\t")
}

func (r *spfResult) format() string {
	s := fmt.Sprintf("spf=%s (sender IP is %s", r.result, r.ip)
	if r.err != nil && r.result != spf.Pass {
		s += "; " + comment(r.err.Error())
	}
	s += ")"
	if r.mailfrom != "" {
		s += " smtp.mailfrom=" + r.mailfrom
	}
	if r.helo != "" {
		s += " smtp.helo=" + r.helo
	}
	return s
}

func (r *dkimResult) format() string {
	s := "dkim=" + r.result
	if r.err != nil {
		s += " (" + comment(r.err.Error()) + ")"
	}
	if r.domain != "" {
		s += " header.d=" + r.domain
	}
	if r.identifier != "" {
		s += " header.i=" + r.identifier
	}
	if r.selector != "" {
		s += " header.s=" + r.selector
	}
	return s
}

// comment makes s safe inside an RFC 5322 comment on one line.
func comment(s string) string {
	return strings.NewReplacer("(", "[", ")", "]", "\\", "/", "\r", " ", "\n", " ").Replace(s)
}
