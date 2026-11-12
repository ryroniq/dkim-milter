package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/textproto"
	"os"
	"strings"

	"github.com/emersion/go-milter"
	"github.com/ryroniq/go-msgauth/dkim"
)

// signingEntry is one line of the signing table in config.go.
type signingEntry struct {
	Pattern  string // suffix of the envelope sender, e.g. "@example.com"
	Domain   string // d=
	Selector string // s=
	KeyFile  string
}

type signingKey struct {
	signingEntry
	key crypto.Signer
}

var signingKeys []signingKey

func loadSigningTable() error {
	for _, e := range signingTable {
		key, err := loadKey(e.KeyFile)
		if err != nil {
			return fmt.Errorf("%s: %w", e.KeyFile, err)
		}
		signingKeys = append(signingKeys, signingKey{e, key})
		log.Printf("loaded %T for %s: d=%s s=%s", key, e.Pattern, e.Domain, e.Selector)
	}
	return nil
}

func loadKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported key type %T", k)
		}
		return s, nil
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

type signSession struct {
	milter.NoOpMilter
	from string
	msg  message
}

func (s *signSession) MailFrom(from string, m *milter.Modifier) (milter.Response, error) {
	s.msg.reset()
	s.from = from
	return milter.RespContinue, nil
}

func (s *signSession) Header(name, value string, m *milter.Modifier) (milter.Response, error) {
	s.msg.addHeader(name, value)
	return milter.RespContinue, nil
}

func (s *signSession) Headers(_ textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	s.msg.endHeaders()
	return milter.RespContinue, nil
}

func (s *signSession) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	s.msg.addBody(chunk)
	return milter.RespContinue, nil
}

func (s *signSession) Abort(m *milter.Modifier) error {
	s.msg.reset()
	s.from = ""
	return nil
}

// Body runs at end of message, the only point where headers may be added.
// It returns Continue rather than Accept: go-milter discards the session
// object after a final verdict, and Postfix treats Continue at EOM as accept.
func (s *signSession) Body(m *milter.Modifier) (milter.Response, error) {
	defer s.msg.reset()
	qid := m.Macros["i"]

	if !s.msg.has("From") {
		log.Printf("%s: no From header, not signing", qid)
		return milter.RespContinue, nil
	}
	keys := []string{"From"}
	for _, h := range signedHeaders {
		if !strings.EqualFold(h, "From") && s.msg.has(h) {
			keys = append(keys, h)
		}
	}

	from := strings.ToLower(s.from)
	signed := false
	for _, k := range signingKeys {
		if !strings.HasSuffix(from, strings.ToLower(k.Pattern)) {
			continue
		}
		sig, err := sign(s.msg.buf.Bytes(), &dkim.SignOptions{
			Domain:                 k.Domain,
			Selector:               k.Selector,
			Signer:                 k.key,
			HeaderKeys:             keys,
			HeaderCanonicalization: dkim.Canonicalization(headerCanonicalization),
			BodyCanonicalization:   dkim.Canonicalization(bodyCanonicalization),
		})
		if err != nil {
			log.Printf("%s: signing d=%s s=%s failed: %v", qid, k.Domain, k.Selector, err)
			return milter.RespTempFail, nil
		}
		if err := m.InsertHeader(0, "DKIM-Signature", s.msg.headerValue(sig)); err != nil {
			return nil, err
		}
		log.Printf("%s: signed from=<%s> d=%s s=%s", qid, s.from, k.Domain, k.Selector)
		signed = true
	}
	if !signed && debug {
		log.Printf("%s: no signing entry for from=<%s>", qid, s.from)
	}
	return milter.RespContinue, nil
}

// sign returns the DKIM-Signature value (without name and final CRLF), folded
// with bare LF as the milter protocol expects.
func sign(raw []byte, opts *dkim.SignOptions) (string, error) {
	signer, err := dkim.NewSigner(opts)
	if err != nil {
		return "", err
	}
	if _, err := signer.Write(raw); err != nil {
		signer.Close()
		return "", err
	}
	if err := signer.Close(); err != nil {
		return "", err
	}
	v := strings.TrimPrefix(signer.Signature(), "DKIM-Signature:")
	return strings.ReplaceAll(strings.TrimSpace(v), "\r\n", "\n"), nil
}
