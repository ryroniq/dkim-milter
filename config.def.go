//go:build ignore

// Configuration. config.def.go holds the defaults and is tracked in git;
// `make` copies it to config.go (untracked) the first time, and config.go is
// what gets compiled. Edit config.go and rebuild. When an update adds a
// setting to config.def.go, the build fails with "undefined: <name>" until
// you copy it into config.go (`diff config.def.go config.go` shows what
// changed).

package main

// Unix socket for each -mode, as a path outside the Postfix chroot. Put them
// in a setgid directory owned by group postfix so the sockets inherit the group.
const signSocket = "/var/spool/postfix/milter/sign/sock"
const verifySocket = "/var/spool/postfix/milter/verify/sock"

// Log every message processed, not just failures and signatures.
const debug = false

// --- sign mode ---

// Every entry whose Pattern is a suffix of the envelope sender (MAIL FROM)
// adds its own DKIM-Signature. KeyFile is a PEM private key (PKCS#8 RSA or
// ed25519, or PKCS#1 RSA). Keys are loaded at startup.
var signingTable = []signingEntry{
	{Pattern: "@example.com", Domain: "example.com", Selector: "selector", KeyFile: "/etc/dkim/example.com.key"},
}

// Headers to sign when present. From is always signed.
var signedHeaders = []string{"Date", "From", "To", "Subject", "Reply-To"}

// Header/body canonicalization: "relaxed" or "simple". Relaxed is safer behind
// a milter, since the milter protocol doesn't carry header whitespace exactly.
const headerCanonicalization = "relaxed"
const bodyCanonicalization = "relaxed"

// --- verify mode ---

// authserv-id used in Authentication-Results. Empty means Postfix's
// $myhostname (milter macro j), or os.Hostname() if Postfix doesn't send it.
// Existing Authentication-Results headers that claim this id are removed.
const authservID = ""

// Header added as "<name>: yes" when SPF is fail/softfail or a DKIM signature
// fails (the OpenSMTPD filter's filter.Junk()). Any such header already in the
// message is removed first. Empty disables both.
const junkHeader = "X-Spam"
