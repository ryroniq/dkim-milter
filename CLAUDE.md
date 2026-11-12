# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Postfix milter port of the author's OpenSMTPD DKIM `signer` and `verify` filters. A single binary runs in one of two modes: `-mode sign` (DKIM-sign outgoing mail) or `-mode verify` (SPF + DKIM check, add `Authentication-Results`).

## Commands

```sh
make                     # creates config.go from config.def.go if missing, builds ./dkim-milter
make test                # go vet + go test (also creates config.go if missing)
go test -run TestSignThenVerify -v .   # single test (config.go must exist)
```

## Configuration is compiled in (suckless style)

- `config.def.go` holds the tracked defaults and has `//go:build ignore`, so it is never compiled. `make` strips that tag and copies it to `config.go` **only when config.go is missing**; `config.go` is gitignored and is what gets built.
- When adding a setting: add it to `config.def.go`, then add it to your local `config.go` too (or delete config.go and rerun `make`). Code that refers to a new setting won't build until config.go has it.
- There are no config files or flags beyond `-mode`.

## Architecture

- `main.go`: picks the mode, sets the go-milter `Server` action/protocol flags for that mode, and creates the unix socket (mode 0660, stale socket replaced).
- `message.go`: rebuilds the raw RFC 5322 message from milter events, which the DKIM library needs. Headers are buffered and written out only at end-of-headers, because whether Postfix honoured `SMFIP_HDR_LEADSPC` (whitespace after the colon kept) is only known after seeing the values. go-milter speaks protocol v2, so leading-space mode is requested but not guaranteed. Folded header lines arrive joined by bare LF; everything is normalized to CRLF. `headerValue()` adds a leading space to headers we add when leading-space mode is on.
- `sign.go` / `verify.go`: one session type per mode, embedding `milter.NoOpMilter`. All work happens in `Body` (end of message), the only point where headers may be modified.

Milter quirks the code relies on:
- `Body` returns `RespContinue`, not `RespAccept`: go-milter replaces the session object after a final verdict, and Postfix treats Continue at EOM as accept. Per-message state is reset in `MailFrom`, `Abort` and a deferred reset in `Body`, since one session handles several messages per connection.
- Values passed to `InsertHeader` must fold with bare LF (`\n\t`), never CRLF. The DKIM library folds its signature with CRLF, so `sign()` converts it.
- `ChangeHeader(idx, name, "")` deletes a header; `idx` is 1-based among headers of that name. Forged `Authentication-Results` and all incoming `junkHeader` headers are deleted from last to first so the indexes stay valid.
- go-milter replaces its macro map on every macro packet, so a macro is only visible in the callback for the stage it was sent with. The queue ID (`i`) is read in `Body` (end-of-data macros); the authserv-id (`j`, Postfix's `$myhostname`) is read in `verifySession.Connect` and kept on the session.

DKIM uses the author's fork `github.com/ryroniq/go-msgauth` (it has `VerifyWithOptions`, `IsTempFail`/`IsPermFail`, `ErrTooManySignatures`), not upstream emersion/go-msgauth.

## Tests

`milter_test.go` runs real sign and verify servers on temp unix sockets with the go-milter client. Each case runs with and without leading-space mode. DNS is stubbed through the package variables `dkimLookupTXT` and `spfOptions` (SPF resolver), and the test sets `signingKeys`/`authservName` directly instead of loading config. The client's `ActionMask` is limited to v2 actions so it accepts go-milter's v2 negotiation reply.
