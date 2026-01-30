.PHONY: build build-linux clean run pxeimage pxeimage-deploy deploy

BINARY=baremetalservices
VERSION=1.0.0
PXE_SERVER=root@pxe.g10.lo
PXE_DIR=/tftpboot

build:
	go build -o $(BINARY) .

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY)-linux .

clean:
	rm -f $(BINARY) $(BINARY)-linux pxeimage/boot/initramfs

run:
	go run .

pxeimage: build-linux
	@echo "Building PXE image..."
	./pxeimage/build.sh

pxeimage-deploy: pxeimage
	@echo "Deploying PXE image to $(PXE_SERVER)..."
	scp pxeimage/boot/initramfs $(PXE_SERVER):$(PXE_DIR)/
	scp pxeimage/boot/vmlinuz $(PXE_SERVER):$(PXE_DIR)/
	scp pxeimage/boot/pxelinux.0 $(PXE_SERVER):$(PXE_DIR)/
	scp pxeimage/boot/ldlinux.c32 $(PXE_SERVER):$(PXE_DIR)/
	scp pxeimage/boot/pxelinux.cfg/default $(PXE_SERVER):$(PXE_DIR)/pxelinux.cfg/
	@echo "Deploy complete."

deploy: pxeimage-deploy
