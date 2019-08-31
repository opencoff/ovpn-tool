// server.go -- server cert creation
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/opencoff/ovpn-tool/pki"
	flag "github.com/opencoff/pflag"
)

type srvdata struct {
	Port uint16
	TLS  []byte
}

// Encode additional info for a server
func encodeAdditional(s *srvdata) ([]byte, error) {

	var b bytes.Buffer
	g := gob.NewEncoder(&b)
	if err := g.Encode(s); err != nil {
		return nil, fmt.Errorf("can't encode additional data: %s", err)
	}

	return b.Bytes(), nil
}

func decodeAdditional(eb []byte) (*srvdata, error) {
	if len(eb) == 0 {
		return nil, nil
	}

	var s srvdata

	b := bytes.NewBuffer(eb)
	g := gob.NewDecoder(b)
	if err := g.Decode(&s); err != nil {
		return nil, fmt.Errorf("can't decode additional data: %s", err)
	}
	return &s, nil
}

// Implement the 'server' command
func ServerCert(db string, args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	fs.Usage = func() {
		serverUsage(fs)
	}

	var yrs uint = 2
	var dns StringList
	var ip net.IP
	var port uint16 = 1194

	fs.UintVarP(&yrs, "validity", "V", yrs, "Issue server certificate with `N` years validity")
	fs.VarP(&dns, "dnsname", "d", "Add `M` to list of DNS names for this server")
	fs.IPVarP(&ip, "ip-address", "i", ip, "Use `S` as the server listening IP address")
	fs.Uint16VarP(&port, "port", "p", port, "Use `P` as the server listening port number")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	args = fs.Args()
	if len(args) < 1 {
		warn("Insufficient arguments to 'server'\n")
		fs.Usage()
	}

	cn := args[0]
	if strings.Index(cn, ".") > 0 {
		dns.V = append(dns.V, cn)
	}

	if len(ip) == 0 && len(dns.V) == 0 {
		warn("No server IP or hostnames specified; generated configs may be incomplete..")
	}

	tlscrypt := make([]byte, 256)
	_, err = io.ReadFull(rand.Reader, tlscrypt)
	if err != nil {
		panic("can't read tlscrypt random bytes")
	}

	sd := &srvdata{
		Port: port,
		TLS:  tlscrypt,
	}

	encA, err := encodeAdditional(sd)
	if err != nil {
		die("%s", err)
	}

	ca := OpenCA(db)
	defer ca.Close()

	ci := &pki.CertInfo{
		Subject:    ca.Crt.Subject,
		Validity:   years(yrs),
		DNSNames:   dns.V,
		IPAddress:  ip,
		Additional: encA,
	}

	ci.Subject.CommonName = cn

	// We don't encrypt server certs
	srv, err := ca.NewServerCert(ci, "")
	if err != nil {
		die("can't create server cert: %s", err)
	}

	Print("New server cert:\n%s\n", Cert(*srv.Crt))
}

func serverUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s server: Issue a new OpenVPN server certificate

Usage: %s DB server [options] CN

Where 'DB' is the CA Database file name and 'CN' is the CommonName for the server.

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}
