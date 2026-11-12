# dkim-milter

Postfix milter that DKIM-signs outgoing mail (`-mode sign`) or checks SPF and
DKIM on incoming mail and adds `Authentication-Results` (`-mode verify`).
Ported from the OpenSMTPD `signer` and `verify` filters.

## Build and configure

Configuration is compiled in, suckless style:

```sh
make          # first run copies config.def.go -> config.go, then builds ./dkim-milter
$EDITOR config.go
make          # rebuild after every config change
make test
```

`config.go` is untracked, so pulling updates never conflicts with your
settings. If an update adds a setting to `config.def.go`, the build fails with
`undefined: <name>`; copy the new lines over (`diff config.def.go config.go`).

## Run

One instance per mode, each as its own user. Only the sign user can read the
keys.

```sh
dkim-milter -mode sign      # listens on signSocket
dkim-milter -mode verify    # listens on verifySocket
```

Sockets are created mode 0660; a stale socket from a crash is replaced. Put
them in a setgid directory owned by group `postfix`, e.g.
`/var/spool/postfix/milter`, so Postfix can connect from inside its chroot.

## Postfix

```
# main.cf
smtpd_milters = unix:milter/verify/sock
non_smtpd_milters = unix:milter/sign/sock
milter_default_action = tempfail

# master.cf, submission service
  -o smtpd_milters=unix:milter/sign/sock
```

## Behaviour

- **sign:** every signing-table entry whose pattern is a suffix of the envelope
  sender adds a DKIM-Signature (relaxed/relaxed by default). A key that fails
  to sign tempfails the message instead of sending it unsigned.
- **verify:** SPF on client IP, HELO and MAIL FROM; DKIM on up to 5 signatures
  (10s per key lookup; a timeout is `temperror`). The authserv-id is
  `authservID` if set, else Postfix's `$myhostname` (milter macro `j`, sent by
  default), else the system hostname. Removes existing `Authentication-Results`
  claiming our authserv-id. Replaces any incoming `X-Spam` header: `X-Spam: yes`
  is added on SPF fail/softfail or DKIM fail/permerror.
- Headers are added only at end of message.

## Header reconstruction

Milters get headers as name/value pairs, so the raw message is rebuilt (see
`message.go`). Folding is preserved. The whitespace after the colon is exact
only if Postfix honours `SMFIP_HDR_LEADSPC`, which is requested but not
guaranteed (go-milter speaks protocol v2). Without it, `simple` header
canonicalization fails for headers with unusual spacing such as `Subject:x`;
`relaxed` is unaffected.

## License

ISC, see `LICENSE`.
