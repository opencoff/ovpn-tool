// user.go -- user cert creation
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/opencoff/ovpn-tool/internal/utils"
	"github.com/opencoff/ovpn-tool/pki"
	flag "github.com/opencoff/pflag"
)

func UserCert(db string, args []string) {
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	fs.Usage = func() {
		userUsage(fs)
	}

	var yrs uint = 2
	var askPw bool
	var email string
	var signer string

	fs.UintVarP(&yrs, "validity", "V", yrs, "Issue user certificate with `N` years validity")
	fs.BoolVarP(&askPw, "password", "p", false, "Ask for a password to protect the user certificate")
	fs.StringVarP(&email, "email", "e", email, "Use `E` as the user's email address")
	fs.StringVarP(&signer, "sign-with", "s", "", "Use `S` as the signing CA [root-CA]")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	args = fs.Args()
	if len(args) < 1 {
		warn("Insufficient arguments to 'user'\n")
		fs.Usage()
	}

	var cn string = args[0]
	var pw string

	if askPw {
		var err error
		prompt := fmt.Sprintf("Enter private-key password for user '%s'", cn)
		pw, err = utils.Askpass(prompt, true)
		if err != nil {
			die("Can't get password: %s", err)
		}
	}

	// use CN as EmailAddress if one is not provided
	if strings.Index(cn, "@") > 0 {
		if len(email) == 0 {
			email = cn
		}
	}

	ca := OpenCA(db)
	if len(signer) > 0 {
		ici := &pki.CertInfo{
			Subject: ca.Crt.Subject,
		}

		ici.Subject.CommonName = signer
		ica, err := ca.NewIntermediateCA(ici)
		if err != nil {
			die("can't find signer %s: %s", signer, err)
		}
		ca = ica
	}
	defer ca.Close()

	ci := &pki.CertInfo{
		Subject:        ca.Crt.Subject,
		Validity:       years(yrs),
		EmailAddresses: []string{email},
	}
	ci.Subject.CommonName = cn

	crt, err := ca.NewClientCert(ci, pw)
	if err != nil {
		die("can't create user cert: %s", err)
	}

	Print("New client cert:\n%s\n", Cert(*crt.Crt))
}

func userUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s user: Issue a new OpenVPN user (client) certificate

Usage: %s DB user [options] CN

Where 'DB' is the CA Database file name and 'CN' is the CommonName for the user.
It is useful to use the user's email address as their common name.

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}
