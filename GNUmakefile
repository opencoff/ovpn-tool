
uname = $(shell uname)
bindir = ./bin/$(shell ./build --print-arch)
tooldir = $(HOME)/bin/$(uname)

bin = $(bindir)/ovpn-tool

.PHONY: all install $(tooldir)

all: $(bin)

$(bin): $(wildcard ./src/*.go)
	./build -s

install: $(bin) $(tooldir)
	-cp -p $(bin) $(tooldir)/

$(tooldir):
	test -d $@ || mkdir -p $@

clean:
	-rm -rf $(bindir)
