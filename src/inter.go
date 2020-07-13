// inter.go - intermediate CA command implementation
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

	"github.com/opencoff/ovpn-tool/pki"
	flag "github.com/opencoff/pflag"
)

// Initialize a new CA or an existing CA
func IntermediateCA(db string, args []string) {

	fs := flag.NewFlagSet("intermediate-ca", flag.ExitOnError)
	fs.Usage = func() {
		intermediateCAUsage(fs)
	}

	var yrs uint = 2

	fs.UintVarP(&yrs, "validity", "V", 5, "Issue CA root cert with `N` years validity")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}
	args = fs.Args()
	if len(args) < 1 {
		warn("Insufficient arguments to 'intermediate-ca'\n")
		fs.Usage()
	}

	ca := OpenCA(db)
	defer ca.Close()

	cn := args[0]

	ci := &pki.CertInfo{
		Subject:  ca.Crt.Subject,
		Validity: years(yrs),
	}

	ci.Subject.CommonName = cn
	ica, err := ca.NewIntermediateCA(ci)
	if err != nil {
		die("%s", err)
	}
	Print("New intermediate CA:\n%s\n", Cert(*ica.Crt))
}

func intermediateCAUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s intermediate-ca: Create an intermediate CA.

This command creates an intermediate CA chained to the root CA.

Usage: %s DB intermediate-ca [options] CN

Where 'DB' is the CA Database file name and 'CN' is the CommonName for the intermediate CA.

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}
