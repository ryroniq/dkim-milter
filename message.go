package main

import (
	"bytes"
	"strings"
)

// message rebuilds one message as raw RFC 5322 bytes from milter events.
//
// The milter protocol delivers each header as a name/value pair, so the raw
// field has to be reconstructed:
//   - Postfix strips the whitespace after the colon unless the milter
//     negotiated SMFIP_HDR_LEADSPC. go-milter announces protocol version 2,
//     so we request it but can't rely on it. If any value starts with
//     whitespace it is in effect and values are used verbatim; otherwise
//     "Name: value" is assumed. Headers are therefore only written out at
//     end of headers, once every value has been seen.
//   - Folded lines arrive joined by bare LF.
//
// Header values and body chunks are normalized to CRLF line endings.
type message struct {
	buf       bytes.Buffer
	headers   []field
	leadSpace bool // MTA keeps leading whitespace in header values
	lastCR    bool // last body byte written was CR (chunks can split CRLF)
}

type field struct {
	name, value string
}

func (m *message) reset() {
	m.buf.Reset()
	m.headers = nil
	m.leadSpace = false
	m.lastCR = false
}

func (m *message) addHeader(name, value string) {
	if value != "" && (value[0] == ' ' || value[0] == '\t') {
		m.leadSpace = true
	}
	m.headers = append(m.headers, field{name, value})
}

func (m *message) endHeaders() {
	for _, f := range m.headers {
		m.buf.WriteString(rawField(f.name, f.value, m.leadSpace))
	}
	m.buf.WriteString("\r\n")
}

func (m *message) addBody(chunk []byte) {
	for _, b := range chunk {
		if b == '\n' && !m.lastCR {
			m.buf.WriteByte('\r')
		}
		m.buf.WriteByte(b)
		m.lastCR = b == '\r'
	}
}

// has reports whether a header with this name is present.
func (m *message) has(name string) bool {
	for _, f := range m.headers {
		if strings.EqualFold(f.name, name) {
			return true
		}
	}
	return false
}

// headerValue formats a value for a header we add, matching the MTA's
// leading-space convention so the result reads "Name: value" either way.
func (m *message) headerValue(v string) string {
	if m.leadSpace {
		return " " + v
	}
	return v
}

// rawField reconstructs one header field, including its final CRLF.
// verbatim means the value still carries its leading whitespace.
func rawField(name, value string, verbatim bool) string {
	if verbatim {
		return name + ":" + toCRLF(value) + "\r\n"
	}
	return name + ": " + toCRLF(value) + "\r\n"
}

func toCRLF(s string) string {
	if !strings.Contains(s, "\n") {
		return s
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}
