package main

import (
	"flag"
	"log"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func main() {
	var db, addr, dn, toolPath, serverCRL, ccdPath, serverIP, vpnSubnet, pwFile string

	toolPath, _ = exec.LookPath("ovpn-tool") // try to populate the default if we can

	flag.StringVar(&toolPath, "t", toolPath, "path to the ovpn-tool executable")
	flag.StringVar(&addr, "a", "127.0.0.1:5555", "IP and port to run on")
	flag.StringVar(&db, "db", "foo.db", "path to the ovpn-tool database")
	flag.StringVar(&dn, "d", "vpn.example.com", "domain name of the VPN server to create clients against")
	flag.StringVar(&vpnSubnet, "s", "10.43.0.0/16", "subnet of the VPN")
	flag.StringVar(&serverIP, "gw", "10.43.0.1", "IP of the VPN Gateway")
	flag.StringVar(&ccdPath, "ccd", "/etc/openvpn/ccd", "domain name of the VPN server to create clients against")
	flag.StringVar(&serverCRL, "crl", "/etc/openvpn/crl.pem", "path to the CRL file used by the openvpn server")
	flag.StringVar(&pwFile, "pw", "pw.secret", "path to the file containing the database password")
	flag.Parse()

	fatalIfEmpty(toolPath, "path to ovpn-tool (-t)")
	fatalIfEmpty(addr, "address to serve on (-a)")
	fatalIfEmpty(db, "database path (-db)")
	fatalIfEmpty(dn, "VPN domain name (-d)")
	fatalIfEmpty(vpnSubnet, "VPN subnet (-s)")
	fatalIfEmpty(serverIP, "VPN gateway IP (-gw)")
	fatalIfEmpty(ccdPath, "CCD path (-ccd)")
	fatalIfEmpty(serverCRL, "server CRL file (-crl)")
	fatalIfEmpty(pwFile, "password file (-pw)")

	fatalIfNotFound(toolPath)
	fatalIfNotFound(pwFile)
	fatalIfNotFound(serverCRL)
	fatalIfNotFound(ccdPath)
	fatalIfNotFound(db)

	if toolPath == "" {
		var err error
		toolPath, err = exec.LookPath("ovpn-tool")
		if err != nil {
			log.Fatalf("couldn't find ovpn-tool in the $PATH")
		}
	}

	ccd := CCD{ccdPath, vpnSubnet, serverIP}
	svr := &server{toolPath, db, dn, serverCRL, pwFile, ccd}

	api := gin.Default()
	svr.setupRoutes(api)

	api.Run(addr)
}

func fatalIfEmpty(v, desc string) {
	if v == "" {
		log.Fatalf("%s must not be empty", desc)
	}
}

func fatalIfNotFound(fn string) {
	_, err := os.Stat(fn)
	if err != nil {
		log.Fatalf("failed to open %s: %s", fn, err)
	}
}
