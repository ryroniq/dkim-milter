// Command dkim-milter is a Postfix milter that DKIM-signs outgoing mail
// (-mode sign) or checks SPF and DKIM on incoming mail (-mode verify).
//
// Run one instance per mode, each under its own user; only the sign user
// needs to read the private keys. Settings live in config.go.
package main

import (
	"flag"
	golog "log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/emersion/go-milter"
)

var log = golog.New(os.Stderr, "", 0)

func main() {
	mode := flag.String("mode", "", "sign or verify")
	flag.Parse()

	var srv *milter.Server
	var socket string
	switch *mode {
	case "sign":
		if err := loadSigningTable(); err != nil {
			log.Fatal(err)
		}
		socket = signSocket
		srv = &milter.Server{
			NewMilter: func() milter.Milter { return &signSession{} },
			Actions:   milter.OptAddHeader,
			Protocol:  milter.OptNoConnect | milter.OptNoHelo | milter.OptNoRcptTo | milter.OptHeaderLeadingSpace,
		}
	case "verify":
		if err := initAuthserv(); err != nil {
			log.Fatal(err)
		}
		socket = verifySocket
		srv = &milter.Server{
			NewMilter: func() milter.Milter { return &verifySession{} },
			Actions:   milter.OptAddHeader | milter.OptChangeHeader,
			Protocol:  milter.OptNoRcptTo | milter.OptHeaderLeadingSpace,
		}
	default:
		flag.Usage()
		os.Exit(2)
	}

	ln, err := listen(socket)
	if err != nil {
		log.Fatal(err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		srv.Close() // closing the listener unlinks the socket
	}()

	log.Printf("%s: listening on %s", *mode, socket)
	if err := srv.Serve(ln); err != nil && err != milter.ErrServerClosed {
		log.Fatal(err)
	}
}

// listen creates the unix socket with mode 0660, replacing a stale socket
// left behind by a crash. The group comes from the (setgid) directory.
func listen(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != os.ModeSocket {
			return nil, &os.PathError{Op: "listen", Path: path, Err: syscall.EEXIST}
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
