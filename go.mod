module github.com/opencoff/ovpn-tool

go 1.14

require (
	github.com/etcd-io/bbolt v1.3.3
	github.com/opencoff/go-pki v0.0.0-00010101000000-000000000000
	github.com/opencoff/go-utils v0.4.1
	github.com/opencoff/pflag v0.5.0
	go.etcd.io/bbolt v1.3.5 // indirect
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
)

replace github.com/opencoff/go-pki => ../go-pki
