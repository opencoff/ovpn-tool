
.PHONY: all test

all:
	./build -s

test:
	go test ./pki

clean:
	-rm -rf ./bin
