// export.go -- Export a certificate & key
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/opencoff/go-pki"
	flag "github.com/opencoff/pflag"
)

// Export an OpenVPN config file for a given server or a user
func ExportCert(db string, args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	fs.Usage = func() {
		exportUsage(fs)
	}

	var outfile string
	var server string
	var templ string
	var prUser, prSrv bool
	var json, showCA bool

	fs.StringVarP(&outfile, "outfile", "o", "", "Write the output to file `F`")
	fs.StringVarP(&server, "server", "s", "", "Export configuration for use with server `S`")
	fs.StringVarP(&templ, "template", "t", "", "Use openvpn config template from file `T`")
	fs.BoolVarP(&prUser, "print-client-template", "", false, "Dump the OpenVPN client template")
	fs.BoolVarP(&prSrv, "print-server-template", "", false, "Dump the OpenVPN server template")
	fs.BoolVarP(&json, "json", "j", false, "Dump DB in JSON format")
	fs.BoolVarP(&showCA, "root-ca", "", false, "Export Root-CA in PEM format")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	args = fs.Args()
	if prUser || prSrv {
		if prUser {
			os.Stdout.WriteString(UserTemplate)
		}

		if prSrv {
			os.Stdout.WriteString(ServerTemplate)
		}

		os.Exit(0)
	}

	ca := OpenCA(db)
	defer ca.Close()

	var out io.Writer = os.Stdout
	if len(outfile) > 0 && outfile != "-" {
		fd := mustOpen(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		defer fd.Close()

		out = fd
	}

	// Handle Json export first
	if json {
		err := ca.ExportJSON(out)
		if err != nil {
			die("can't dump db: %s", err)
		}
		os.Exit(0)
	}

	if showCA {
		fmt.Fprintf(out, "%s\n", ca.PEM())
		os.Exit(0)
	}

	if len(args) == 0 {
		fs.Usage()
	}
	cn := args[0]

	// 1. We prefer to use a user supplied template if provided
	// 2. Else, we use an internal/hardcoded template

	var template string
	if len(templ) > 0 {
		buf, err := ioutil.ReadFile(templ)
		if err != nil {
			die("can't read template %s: %s", templ, err)
		}

		template = string(buf)
	}

	var srv *pki.Cert
	if len(server) > 0 {
		// we ignore the unusual case exporting server config for use itself
		if server != cn {
			srv, err = ca.FindServer(server)
			if err != nil {
				die("Can't find server with name '%s': %s", server, err)
			}
		}
	}
	x := &exported{
		Date: time.Now().UTC().Format(time.RFC1123Z),
		Tool: toolInfo(),
		IP:   "0.0.0.0",
		Port: 1194,
	}

	if s, err := ca.FindServer(cn); err == nil {
		if len(template) == 0 {
			template = ServerTemplate
		}

		x.fillCA(s, ca)
		x.exportServer(s, template, out)
		return
	}

	if c, err := ca.FindClient(cn); err == nil {
		if len(template) == 0 {
			template = UserTemplate
		}

		x.fillCA(c, ca)
		x.exportUser(c, srv, template, out)
		return
	}

	die("Can't find server or user %s", cn)
}

type exported struct {
	CommonName string
	Date       string
	Tool       string
	Cert       string
	Key        string
	Ca         string
	TlsCrypt   string

	ServerCommonName string

	// IP Address of server. If present, this is used for server.
	IP string

	// DNS name of the server. If present, this is used for the client.
	// The client template can choose one over the other.
	Host string
	Port uint16
}

func (x *exported) exportServer(s *pki.Cert, t string, out io.Writer) {
	tmpl, err := template.New("ovpn-server").Parse(t)
	if err != nil {
		die("can't parse server template: %s", err)
	}

	x.fill(s, s)
	err = tmpl.Execute(out, x)
	if err != nil {
		die("Can't fill out template: %s", err)
	}
}

// Build the CA chain and print it
func (x *exported) fillCA(s *pki.Cert, ca *pki.CA) {
	calist, err := ca.ChainFor(s)
	if err != nil {
		die("can't build CA chain for %s: %s", s.Subject.CommonName, err)
	}
	var w strings.Builder
	for i := range calist {
		c := calist[i]
		w.Write(c.PEM())
	}
	x.Ca = w.String()
}

func (x *exported) exportUser(c *pki.Cert, srv *pki.Cert, t string, out io.Writer) {
	tmpl, err := template.New("ovpn-client").Parse(t)
	if err != nil {
		die("can't parse client template: %s", err)
	}

	x.fill(srv, c)
	err = tmpl.Execute(out, x)
	if err != nil {
		die("Can't fill out template: %s", err)
	}
}

func (x *exported) fill(s *pki.Cert, c *pki.Cert) {
	if s != nil {
		sd, err := decodeAdditional(s.Additional)
		if err != nil {
			die("%s", err)
		}

		x.ServerCommonName = s.Subject.CommonName
		if len(s.IPAddresses) > 0 {
			x.IP = s.IPAddresses[0].String()
		}

		// We only use the first name in the DNSNames list - if it is present.
		if len(s.DNSNames) > 0 {
			x.Host = s.DNSNames[0]
		} else {
			// Punt and use the IP address.
			// This way, the client template can refer to .Host to
			// get the Hostname or IP address
			x.Host = x.IP
		}

		if sd != nil {
			x.Port = sd.Port
			if x.Port == 0 {
				x.Port = 1194
			}

			if len(sd.TLS) > 0 {
				x.TlsCrypt = fmtTLS(sd.TLS)
			}
		}
	}

	crt, key := c.PEM()
	x.Cert = string(crt)
	x.Key = string(key)
	x.CommonName = c.Subject.CommonName
}

func mustOpen(fn string, flag int) *os.File {
	fdk, err := os.OpenFile(fn, flag, 0600)
	if err != nil {
		die("can't open file %s: %s", fn, err)
	}
	return fdk
}

func toolInfo() string {
	return fmt.Sprintf("%s %s [%s]", path.Base(os.Args[0]), ProductVersion, RepoVersion)
}

func fmtTLS(b []byte) string {
	if len(b) < 256 {
		die("tls-crypt bytes are less than 256?")
	}

	const prefix string = `# DoS protection for TLS control channel
# encrypts & HMACs control channel with this symmetric key.
# Shared between server & clients.
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
`

	var s strings.Builder
	s.WriteString(prefix)
	for i := 0; i < 256; i += 16 {
		for j := 0; j < 16; j++ {
			v := b[j+i]
			s.WriteString(fmt.Sprintf("%02x", v))
		}

		s.WriteRune('\n')
	}

	s.WriteString("-----END OpenVPN Static key V1-----\n</tls-crypt>\n")
	return s.String()
}

func exportUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s export: Export a OpenVPN server or client configuration

Usage: %s DB export [options] CN

Where 'DB' is the CA Database file and 'CN' is the CommonName of the
server or client configuration to be exported.

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}

// default template.
const ServerTemplate string = `# OpenVPN Server Configuration for {{ .CommonName }}
# Autogenerated by {{ .Tool }}
#    on {{ .Date }}

mode server
tls-server
proto udp
dev tun

local {{ .IP }}
port {{ .Port }}

topology subnet
push "topology subnet"

# IP Address of the VPN Tunnel
ifconfig 10.33.44.1 255.255.255.0

# Range of IPs to give out to the clients
ifconfig-pool 10.33.44.10 10.33.44.254 255.255.255.0

# Maintain a record of client <-> virtual IP address associations in this file
ifconfig-pool-persist /var/run/openvpn/ipp.txt


# Run unbound at this tunnel address
push "dhcp-option DNS 10.33.44.1"

# Google & Cloudflare servers
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 1.1.1.1"

# VPN server is the default gw for all traffic
# If you only want this for some clients, put this line in the client
# specific directory "ccd/$COMMONNAME" - *AND* comment out this globally.
push "route-gateway 10.33.44.1"
push "redirect-gateway def1"

# opinionated tls config
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
cipher AES-256-GCM
ncp-ciphers AES-256-GCM
#ecdh-curve ED25519
tls-version-min 1.2

# client specific directory
client-config-dir ccd

# keepalive; battery friendly value
keepalive 180 360

compress lz4
push "compress lz4"

# We won't use a DH params file - since we are using
# ECC certs
dh none
passtos

# EDIT: This is platform specific; edit as needed
user nobody
group nogroup

persist-tun

# Output a short status file showing current connections, truncated
# and rewritten every minute.
status /tmp/openvpn-status.log

# 0 is silent, except for fatal errors
# 4 is reasonable for general usage
# 5 and 6 can help to debug connection problems
# 9 is extremely verbose
verb 3

# Silence repeating messages.  At most 20 sequential messages of the
# same message category will be output to the log.
mute 20

# Management console
# mgmt.passwd is the name of the password file in /etc/openvpn
# This file must contain the password on a single line
#management 127.0.0.1 11940 mgmt.passwd

# Inline certs, keys and tls-crypt follows
<ca>
{{ .Ca }}</ca>
<cert>
{{ .Cert }}</cert>
<key>
{{ .Key }}</key>
{{ .TlsCrypt }}

`

const UserTemplate string = `# OpenVPN Client Config for {{ .CommonName }}
# Autogenerated by {{ .Tool }}
#    on {{ .Date }}
client
tls-client
dev tun
proto udp
remote {{ .Host }} {{ .Port }}
resolv-retry infinite
nobind
verb 3

passtos
route-delay 4
script-security 2

# Opionated cipher list for TLS
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
cipher AES-256-GCM
auth-nocache
remote-cert-tls server
tls-version-min 1.2

# Verify the remote server's common name
verify-x509-name "{{ .ServerCommonName }}"

# Inline certs, keys and tls-crypt follows
<ca>
{{ .Ca }}</ca>
<cert>
{{ .Cert }}</cert>
<key>
{{ .Key }}</key>
{{ .TlsCrypt }}
`

// EOF
