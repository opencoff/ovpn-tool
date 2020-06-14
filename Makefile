VERSION := $(shell git describe --tags|tr -d 'v')

.PHONY: all test

all:
	./build -s
	go build -o ./bin/ovpn-api ./cmd/api

test:
	go test ./pki

clean:
	-rm -rf ./bin

pkg: all
	mkdir -p dpkg/usr/bin
	cp bin/linux-amd64/ovpn-tool dpkg/usr/bin
	cp bin/ovpn-api dpkg/usr/bin
	IAN_DIR=dpkg ian set -v ${VERSION}
	IAN_DIR=dpkg ian pkg