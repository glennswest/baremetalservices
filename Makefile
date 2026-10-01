.PHONY: build build-linux clean run test pxeimage iso

# Images are built on dev.g8.lo as stormcentral goldens (deploy/build-golden.sh,
# `sc-build test/run.sh`); the targets below are for local development.
BINARY=baremetalservices
VERSION=1.0.0

build:
	go build -o $(BINARY) .

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY)-linux .

clean:
	rm -f $(BINARY) $(BINARY)-linux pxeimage/boot/initramfs

run:
	go run .

test:
	go vet ./... && go test ./...

pxeimage: build-linux
	./pxeimage/build.sh

iso: pxeimage
	./pxeimage/build-iso.sh
