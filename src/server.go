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

	"github.com/opencoff/go-pki"
	flag "github.com/opencoff/pflag"
)

type srvdata struct {
	Port uint16
	TLS  []byte
}

// Implement the 'server' command
func ServerCert(db string, args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	fs.Usage = func() {
		serverUsage(fs)
	}

	var yrs uint = 2
	var dns []string
	var ip []net.IP
	var port uint16 = 1194
	var signer, envpw string

	fs.UintVarP(&yrs, "validity", "V", yrs, "Issue server certificate with `N` years validity")
	fs.StringSliceVarP(&dns, "dnsname", "d", []string{}, "Add `M` to list of DNS names for this server")
	fs.IPSliceVarP(&ip, "ip-address", "i", []net.IP{}, "Add `IP` to list of IP addresses for this server")
	fs.Uint16VarP(&port, "port", "p", port, "Use `P` as the server listening port number")
	fs.StringVarP(&signer, "sign-with", "s", "", "Use `S` as the signing CA [root-CA]")
	fs.StringVarP(&envpw, "env-password", "E", "", "Use password from environment var `E`")

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
		dns = append(dns, cn)
	}

	if len(ip) == 0 && len(dns) == 0 {
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

	ca := OpenCA(db, envpw)
	if len(signer) > 0 {
		ica, err := ca.FindCA(signer)
		if err != nil {
			die("can't find signer %s: %s", signer, err)
		}
		ca = ica
	}
	defer ca.Close()

	ci := &pki.CertInfo{
		Subject:    ca.Subject,
		Validity:   years(yrs),
		DNSNames:   []string(dns),
		Additional: encA,
	}
	ci.Subject.CommonName = cn
	if len(ip) > 0 {
		ci.IPAddresses = []net.IP(ip)
	}

	// We don't encrypt server certs
	srv, err := ca.NewServerCert(ci, "")
	if err != nil {
		die("can't create server cert: %s", err)
	}

	Print("New server cert:\n%s\n", Cert(*srv.Certificate))
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
